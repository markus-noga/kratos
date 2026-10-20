// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/pkg"
)

func TestMetricsRouterPaths(t *testing.T) {
	// TODO refactor this test to be parallelizable once we rewrite the server setup to be properly testable
	ports, err := freeport.GetFreePorts(2)
	require.NoError(t, err)
	adminPort, publicPort := ports[0], ports[1]
	cmd := &cobra.Command{}
	cmd.Flags().Bool("sqa-opt-out", true, "")
	_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(map[string]any{
		"serve.admin.port":  adminPort,
		"serve.public.port": publicPort,
	}))

	startAdmin, err := serveAdmin(t.Context(), reg, cmd)
	require.NoError(t, err)
	startPublic, err := servePublic(t.Context(), reg, cmd)
	require.NoError(t, err)
	eg, _ := errgroup.WithContext(t.Context())
	eg.Go(startAdmin)
	eg.Go(startPublic)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health/ready", publicPort))
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equalf(t, http.StatusOK, resp.StatusCode, "%s", body)
	}, 2*time.Second, 10*time.Millisecond)

	// Make some requests that should be recorded in the metrics
	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://127.0.0.1:%d/sessions/session-id", publicPort), nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/identities/8e5f29ec-db29-4e56-8517-75f7d4e2f1bc/sessions", adminPort))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		res, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/metrics/prometheus", adminPort))
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, res.StatusCode)
		respBody, err := io.ReadAll(res.Body)
		body := string(respBody)

		require.NoError(t, err)
		assert.Contains(t, body, `endpoint="/sessions/{param}"`)
		assert.Contains(t, body, `endpoint="/admin/identities/{param}/sessions"`)
	}, 5*time.Second, 100*time.Millisecond)
}

func TestClientInfoMiddleware(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		values  map[string]any
		peer    string
		spoofed string
		want    string
	}{
		{name: "unset ignores the header", peer: "198.51.100.7:1", spoofed: "1.2.3.4", want: "198.51.100.7"},
		{name: "untrusted peer", peer: "198.51.100.7:1", spoofed: "1.2.3.4", want: "198.51.100.7",
			values: map[string]any{"defense.client_ip.header": "True-Client-IP", "defense.client_ip.trusted_proxies": []string{"10.0.0.0/8"}}},
		{name: "trusted peer", peer: "10.1.2.3:1", spoofed: "1.2.3.4", want: "1.2.3.4",
			values: map[string]any{"defense.client_ip.header": "True-Client-IP", "defense.client_ip.trusted_proxies": []string{"10.0.0.0/8"}}},
		{name: "invalid setting trusts nobody", peer: "10.1.2.3:1", spoofed: "1.2.3.4", want: "10.1.2.3",
			values: map[string]any{"defense.client_ip.header": "True-Client-IP", "defense.client_ip.trusted_proxies": []string{"10.0.0.0/8", "nope"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(tc.values))

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("True-Client-IP", tc.spoofed)
			var got string
			clientInfoMiddleware(reg)(httptest.NewRecorder(), r, func(_ http.ResponseWriter, r *http.Request) {
				got = httpx.ClientIP(r)
			})
			assert.Equal(t, tc.want, got)
		})
	}
}

// serveRegistry returns a registry for servePublic with the defense d (nil: the
// no-op one) and the values, with secrets.default unset unless they set it;
// madeUp reads it first. The registry is initialized, so that a servePublic
// without the check runs through and the test fails by its assertion, not by a
// nil persister.
func serveRegistry(t *testing.T, d defense.Defense, values map[string]any, madeUp bool) *driver.RegistryDefault {
	t.Helper()
	_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValue(config.ViperKeySecretsDefault, []string{}), configx.WithValues(values))
	if d != nil {
		reg.WithDefense(d)
	}
	if madeUp {
		reg.Config().SecretsDefault(t.Context())
	}
	return reg
}

// serveCmd is a command with the flag of serve that servePublic reads.
func serveCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("sqa-opt-out", true, "")
	return cmd
}

// A defense keyed with a secret made up for this process would give every
// replica, and every restart, counters of their own: serve refuses to start.
func TestServePublicNeedsAConfiguredFingerprintSecret(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		defense defense.Defense
		values  map[string]any
		madeUp  bool // SecretsDefault was read before, as the cookie store does
		ok      bool
	}{
		{name: "no defense needs none", madeUp: true, ok: true},
		{name: "a defense without a secret", defense: new(defensetest.Recorder)},
		{name: "a defense with a made-up secrets.default", defense: new(defensetest.Recorder), madeUp: true},
		{name: "a defense with fingerprint_key", defense: new(defensetest.Recorder), madeUp: true, ok: true,
			values: map[string]any{config.ViperKeyDefenseFingerprintKey: "fingerprint-key"}},
		{name: "a defense with secrets.default", defense: new(defensetest.Recorder), ok: true,
			values: map[string]any{config.ViperKeySecretsDefault: []string{"default-secret"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := serveRegistry(t, tc.defense, tc.values, tc.madeUp)

			err := checkDefenseFingerprintSecret(t.Context(), reg)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "defense.fingerprint_key")
			_, err = servePublic(t.Context(), reg, serveCmd())
			assert.ErrorContains(t, err, "defense.fingerprint_key", "servePublic runs the check")
		})
	}
}

// A known device cookie signed with a key made up for this process would verify
// only on the replica that issued it, until it restarts: serve refuses to start
// a defense with it. defense.fingerprint_key, set in every case, does not sign it.
func TestServePublicNeedsAConfiguredKnownDeviceCookieSecret(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		noop   bool // no defense; else one that uses the verdict or not
		uses   bool
		values map[string]any
		madeUp bool // SecretsDefault was read before, as the cookie store does
		ok     bool
	}{
		{name: "no defense needs none, even with the cookie forced on", noop: true, madeUp: true, ok: true,
			values: map[string]any{config.ViperKeyKnownDeviceCookieEnabled: true}},
		{name: "a defense that uses the verdict, without a cookie secret", uses: true},
		{name: "a defense that uses the verdict, with a made-up secrets.default", uses: true, madeUp: true},
		{name: "a defense that uses the verdict, with known_device_cookie.secrets", uses: true, madeUp: true, ok: true,
			values: map[string]any{config.ViperKeyKnownDeviceCookieSecrets: []string{"cookie-secret"}}},
		{name: "a defense that uses the verdict, with secrets.default", uses: true, ok: true,
			values: map[string]any{config.ViperKeySecretsDefault: []string{"default-secret"}}},
		{name: "a defense that does not use it leaves the cookie off", madeUp: true, ok: true},
		{name: "the cookie forced on, for a defense that does not use it",
			values: map[string]any{config.ViperKeyKnownDeviceCookieEnabled: true}},
		{name: "the cookie forced off", uses: true, madeUp: true, ok: true,
			values: map[string]any{config.ViperKeyKnownDeviceCookieEnabled: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var d defense.Defense
			if !tc.noop {
				rec := new(defensetest.Recorder)
				rec.UseKnownDeviceVerdict(tc.uses)
				d = rec
			}
			values := map[string]any{config.ViperKeyDefenseFingerprintKey: "fingerprint-key"}
			maps.Copy(values, tc.values)
			reg := serveRegistry(t, d, values, tc.madeUp)

			err := checkKnownDeviceCookieSecret(t.Context(), reg)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "defense.known_device_cookie.secrets")
			_, err = servePublic(t.Context(), reg, serveCmd())
			assert.ErrorContains(t, err, "defense.known_device_cookie.secrets", "servePublic runs the check")
		})
	}
}
