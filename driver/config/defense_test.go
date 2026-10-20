// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/embedx"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
)

// The default is documented in the config schema and applied in code: they
// must say the same.
func TestDefenseMaxDelayDefaultMatchesSchema(t *testing.T) {
	t.Parallel()
	got := gjson.GetBytes(embedx.ConfigSchema, "properties.defense.properties.max_delay.default").String()
	assert.Equal(t, config.DefenseDefaultMaxDelay.String(), got)
	assert.Equal(t, "10s", got)
}

func TestDefenseTrustedProxies(t *testing.T) {
	t.Parallel()
	newCfg := func(opts ...configx.OptionModifier) *config.Config {
		return config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, append(opts, configx.SkipValidation())...)
	}
	req := func(peer, header, value string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer
		r.Header.Set(header, value)
		return r
	}

	t.Run("case=unset trusts nobody", func(t *testing.T) {
		t.Parallel()
		tp, err := newCfg().DefenseTrustedProxies(t.Context())
		require.NoError(t, err)
		r := req("10.0.0.1:1", "True-Client-IP", "1.2.3.4")
		assert.Equal(t, "10.0.0.1", tp.ClientIP(r))
	})

	t.Run("case=configured", func(t *testing.T) {
		t.Parallel()
		c := newCfg(
			configx.WithValue(config.ViperKeyDefenseClientIPHeader, "True-Client-IP"),
			configx.WithValue(config.ViperKeyDefenseClientIPTrustedProxies, []string{"10.0.0.0/8"}),
		)
		tp, err := c.DefenseTrustedProxies(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", tp.ClientIP(req("10.0.0.1:1", "True-Client-IP", "1.2.3.4")))
		assert.Equal(t, "198.51.100.7", tp.ClientIP(req("198.51.100.7:1", "True-Client-IP", "1.2.3.4")))
	})

	t.Run("case=invalid CIDR is an error", func(t *testing.T) {
		t.Parallel()
		c := newCfg(configx.WithValue(config.ViperKeyDefenseClientIPTrustedProxies, []string{"nope"}))
		_, err := c.DefenseTrustedProxies(t.Context())
		require.Error(t, err)
	})
}

func TestDefenseFingerprintSecretConfigured(t *testing.T) {
	t.Parallel()
	key := configx.WithValue(config.ViperKeyDefenseFingerprintKey, "fingerprint-key")
	def := configx.WithValue(config.ViperKeySecretsDefault, []string{"default-secret"})

	for _, tc := range []struct {
		name   string
		opts   []configx.OptionModifier
		madeUp bool // SecretsDefault was read before, as the cookie store does
		want   bool
	}{
		{name: "neither set"},
		{name: "secrets.default made up", madeUp: true},
		{name: "fingerprint_key", opts: []configx.OptionModifier{key}, want: true},
		{name: "fingerprint_key and a made-up secrets.default", opts: []configx.OptionModifier{key}, madeUp: true, want: true},
		{name: "secrets.default", opts: []configx.OptionModifier{def}, want: true},
		{name: "secrets.default read before", opts: []configx.OptionModifier{def}, madeUp: true, want: true},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			c := config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, append(tc.opts, configx.SkipValidation())...)
			if tc.madeUp {
				c.SecretsDefault(t.Context())
			}
			assert.Equal(t, tc.want, c.DefenseFingerprintSecretConfigured(t.Context()))
		})
	}
}

func TestKnownDeviceCookieSecretsConfigured(t *testing.T) {
	t.Parallel()
	cookie := configx.WithValue(config.ViperKeyKnownDeviceCookieSecrets, []string{"cookie-secret"})
	def := configx.WithValue(config.ViperKeySecretsDefault, []string{"default-secret"})
	key := configx.WithValue(config.ViperKeyDefenseFingerprintKey, "fingerprint-key")

	for _, tc := range []struct {
		name   string
		opts   []configx.OptionModifier
		madeUp bool // SecretsDefault was read before, as the cookie store does
		want   bool
	}{
		{name: "neither set"},
		{name: "secrets.default made up", madeUp: true},
		{name: "fingerprint_key does not sign the cookie", opts: []configx.OptionModifier{key}, madeUp: true},
		{name: "known_device_cookie.secrets", opts: []configx.OptionModifier{cookie}, want: true},
		{name: "known_device_cookie.secrets and a made-up secrets.default", opts: []configx.OptionModifier{cookie}, madeUp: true, want: true},
		{name: "secrets.default", opts: []configx.OptionModifier{def}, want: true},
		{name: "secrets.default read before", opts: []configx.OptionModifier{def}, madeUp: true, want: true},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()
			c := config.MustNew(t, logrusx.New("", ""), &contextx.Default{}, append(tc.opts, configx.SkipValidation())...)
			if tc.madeUp {
				c.SecretsDefault(t.Context())
			}
			assert.Equal(t, tc.want, c.KnownDeviceCookieSecretsConfigured(t.Context()))
		})
	}
}
