// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package courier_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ory/kratos/courier"
	templates "github.com/ory/kratos/courier/template/email"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/x/events"
	"github.com/ory/x/configx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/otelx/semconv"
)

func queueNewMessage(t *testing.T, c courier.Courier) uuid.UUID {
	t.Helper()
	id, err := c.QueueEmail(t.Context(), templates.NewTestStub(&templates.TestStubModel{
		To:      "test-recipient-1@example.org",
		Subject: "test-subject-1",
		Body:    "test-body-1",
	}))
	require.NoError(t, err)
	return id
}

func TestDispatchMessageWithInvalidSMTP(t *testing.T) {
	_, reg := pkg.NewRegistryDefaultWithDSN(t, "", configx.WithValues(map[string]any{
		config.ViperKeyCourierMessageRetries: 5,
		config.ViperKeyCourierSMTPURL:        "http://foo.url",
	}))

	c, err := reg.Courier(t.Context())
	require.NoError(t, err)

	t.Run("case=failed sending", func(t *testing.T) {
		id := queueNewMessage(t, c)
		message, err := reg.CourierPersister().LatestQueuedMessage(t.Context())
		require.NoError(t, err)
		require.Equal(t, id, message.ID)

		err = c.DispatchMessage(t.Context(), *message)
		// sending the email fails, because there is no SMTP server at foo.url
		require.Error(t, err)

		messages, err := reg.CourierPersister().NextMessages(t.Context(), 10)
		require.NoError(t, err)
		require.Len(t, messages, 1)
	})
}

func TestDispatchMessage(t *testing.T) {
	_, reg := pkg.NewRegistryDefaultWithDSN(t, "", configx.WithValues(map[string]any{
		config.ViperKeyCourierMessageRetries: 5,
		config.ViperKeyCourierSMTPURL:        "http://foo.url",
	}))

	c, err := reg.Courier(t.Context())
	require.NoError(t, err)
	t.Run("case=invalid channel", func(t *testing.T) {
		message := courier.Message{
			Channel:      "invalid-channel",
			Status:       courier.MessageStatusQueued,
			Type:         courier.MessageTypeEmail,
			Recipient:    testhelpers.RandomEmail(),
			Subject:      "test-subject-1",
			Body:         "test-body-1",
			TemplateType: "stub",
		}
		require.NoError(t, reg.CourierPersister().AddMessage(t.Context(), &message))
		assert.ErrorContains(t, c.DispatchMessage(t.Context(), message), "no courier channels configured for: invalid-channel")
	})
}

func TestDispatchQueue(t *testing.T) {
	_, reg := pkg.NewRegistryDefaultWithDSN(t, "", configx.WithValue(config.ViperKeyCourierMessageRetries, 1))

	c, err := reg.Courier(t.Context())
	require.NoError(t, err)
	c.FailOnDispatchError()

	id := queueNewMessage(t, c)
	require.NotEqual(t, uuid.Nil, id)

	// Fails to deliver the first time
	err = c.DispatchQueue(t.Context())
	require.Error(t, err)

	// Retry once, as we set above - still fails
	err = c.DispatchQueue(t.Context())
	require.Error(t, err)

	// Now it has been retried once, which means 2 > 1 is true and it is no longer tried
	err = c.DispatchQueue(t.Context())
	require.NoError(t, err)

	var message courier.Message
	err = reg.Persister().GetConnection(t.Context()).
		Where("status = ?", courier.MessageStatusAbandoned).
		Eager("Dispatches").
		First(&message)

	require.NoError(t, err)
	require.Equal(t, id, message.ID)

	require.Len(t, message.Dispatches, 2)
	require.Contains(t, gjson.GetBytes(message.Dispatches[0].Error, "reason").String(), "failed to send email via smtp")
	require.Contains(t, gjson.GetBytes(message.Dispatches[1].Error, "reason").String(), "failed to send email via smtp")
}

func TestDispatchMessageEmitsEventWithNID(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	requestConfig := fmt.Sprintf(`{"url": "%s", "method": "POST", "body": "file://./stub/request.config.mailer.jsonnet"}`, srv.URL)

	_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(map[string]any{
		config.ViperKeyCourierDeliveryStrategy:  "http",
		config.ViperKeyCourierHTTPRequestConfig: requestConfig,
	}))

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	reg.SetTracer(otelx.NewNoop().WithOTLP(provider.Tracer("test")))

	c, err := reg.Courier(t.Context())
	require.NoError(t, err)

	_, err = c.QueueEmail(t.Context(), templates.NewTestStub(&templates.TestStubModel{
		To:      testhelpers.RandomEmail(),
		Subject: "test-subject",
		Body:    "test-body",
	}))
	require.NoError(t, err)

	require.NoError(t, c.DispatchQueue(t.Context()))

	ended := recorder.Ended()
	i := slices.IndexFunc(ended, func(sp sdktrace.ReadOnlySpan) bool {
		return sp.Name() == "courier.DispatchMessage"
	})
	require.GreaterOrEqual(t, i, 0, "courier.DispatchMessage span not found")

	evs := ended[i].Events()
	j := slices.IndexFunc(evs, func(ev sdktrace.Event) bool {
		return ev.Name == events.CourierMessageDispatched.String()
	})
	require.GreaterOrEqual(t, j, 0, "CourierMessageDispatched event not found on span")

	attrs := evs[j].Attributes
	k := slices.IndexFunc([]attribute.KeyValue(attrs), func(a attribute.KeyValue) bool {
		return string(a.Key) == semconv.AttributeKeyNID.String()
	})
	require.GreaterOrEqual(t, k, 0, "NID attribute not found on event")
	assert.NotEmpty(t, attrs[k].Value.AsString())
}

// Kratos' code templates put the code into the subject ("Use code 123456 to log
// in"), and the body holds it too: no log line of a failed delivery may contain
// it, at any level.
func TestDispatchLogsNoCode(t *testing.T) {
	t.Parallel()

	// dispatch queues a message with a code, runs the queue once and returns
	// what was logged. Each case has its own registry, logger and server.
	dispatch := func(t *testing.T, values map[string]any) []*logrus.Entry {
		t.Helper()
		_, reg := pkg.NewRegistryDefaultWithDSN(t, "", configx.WithValues(values))
		// The test registry logs errors only; warnings and debug lines count too.
		reg.Logger().Logger.SetLevel(logrus.TraceLevel)
		hook := logtest.NewLocal(reg.Logger().Logger)

		c, err := reg.Courier(t.Context())
		require.NoError(t, err)
		_, err = c.QueueEmail(t.Context(), templates.NewTestStub(&templates.TestStubModel{
			To:      "user@example.org",
			Subject: "Use code 987654 to log in",
			Body:    "Your code is 987654",
		}))
		require.NoError(t, err)
		require.NoError(t, c.DispatchQueue(t.Context()))
		return hook.AllEntries()
	}
	assertNoCode := func(t *testing.T, entries []*logrus.Entry) {
		t.Helper()
		var warnings int
		for _, e := range entries {
			if e.Level <= logrus.WarnLevel {
				warnings++
			}
			line, err := e.String()
			require.NoError(t, err)
			assert.NotContains(t, line, "987654")
		}
		assert.NotZero(t, warnings, "the failure is logged")
	}
	smtpValues := func(smtpURL string) map[string]any {
		return map[string]any{
			config.ViperKeyCourierSMTPURL:              smtpURL,
			config.ViperKeyCourierSMTPFrom:             "from@example.org",
			config.ViperKeyClientSMTPNoPrivateIPRanges: false,
		}
	}

	t.Run("case=the SMTP server rejects the message", func(t *testing.T) {
		t.Parallel()
		smtpURL, _ := newReplyingSMTPServer(t, func(int) string { return "554 5.7.1 Message rejected" })
		assertNoCode(t, dispatch(t, smtpValues(smtpURL)))
	})

	t.Run("case=the SMTP server hangs up", func(t *testing.T) {
		t.Parallel()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		assertNoCode(t, dispatch(t, smtpValues(fmt.Sprintf("smtp://%s/?disable_starttls=true", l.Addr()))))
	})

	// Mail APIs may echo a request they reject, and with it the message. The HTTP
	// client gives up on a 5xx itself; any other status reaches the channel.
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadRequest} {
		t.Run(fmt.Sprintf("case=the HTTP provider answers %d, echoing the request", status), func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.Copy(w, r.Body)
			}))
			t.Cleanup(srv.Close)
			assertNoCode(t, dispatch(t, map[string]any{
				config.ViperKeyCourierDeliveryStrategy:  "http",
				config.ViperKeyCourierHTTPRequestConfig: fmt.Sprintf(`{"url": %q, "method": "POST", "body": "file://./stub/request.config.mailer.jsonnet"}`, srv.URL),
			}))
		})
	}
}
