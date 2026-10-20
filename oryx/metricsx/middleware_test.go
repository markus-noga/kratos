// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package metricsx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/analytics-go/v5"

	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
)

// An operator who opts out gets no telemetry at all, not even the startup event
// that says so. The cases run one at a time: New keeps one Service per process,
// which each case resets, and one sets an environment variable.
func TestOptOutSendsNothing(t *testing.T) {
	newCommand := func(t *testing.T, optOut bool) *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().Bool("sqa-opt-out", false, "")
		if optOut {
			require.NoError(t, cmd.Flags().Set("sqa-opt-out", "true"))
		}
		return cmd
	}
	newConfig := func(t *testing.T, values map[string]any) *configx.Provider {
		c, err := configx.New(t.Context(), []byte(`{}`), configx.SkipValidation(), configx.DisableEnvLoading(), configx.WithValues(values))
		require.NoError(t, err)
		return c
	}

	for name, optOut := range map[string]func(t *testing.T) (*cobra.Command, *configx.Provider){
		"--sqa-opt-out": func(t *testing.T) (*cobra.Command, *configx.Provider) {
			return newCommand(t, true), newConfig(t, nil)
		},
		"sqa.opt_out": func(t *testing.T) (*cobra.Command, *configx.Provider) {
			return newCommand(t, false), newConfig(t, map[string]any{"sqa.opt_out": true})
		},
		"SQA_OPT_OUT": func(t *testing.T) (*cobra.Command, *configx.Provider) {
			t.Setenv("SQA_OPT_OUT", "true")
			return newCommand(t, false), newConfig(t, nil)
		},
	} {
		t.Run("case="+name, func(t *testing.T) {
			var (
				mu    sync.Mutex
				types []int
			)
			endpoint := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				var b struct {
					Batch []struct {
						Type int `json:"t"`
					} `json:"batch"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				mu.Lock()
				defer mu.Unlock()
				for _, m := range b.Batch {
					types = append(types, m.Type)
				}
			}))
			t.Cleanup(endpoint.Close)
			cmd, config := optOut(t)
			l := logrusx.New("", "")

			lock.Lock()
			instance = nil
			lock.Unlock()

			synctest.Test(t, func(t *testing.T) {
				s := New(cmd, l, config, &Options{
					Service:      "test",
					DeploymentId: "test",
					WriteKey:     "test",
					Config: &analytics.Config{
						Endpoint: endpoint.URL,
						// No idle connection outlives the bubble.
						Transport: &http.Transport{DisableKeepAlives: true},
					},
				})
				synctest.Wait() // what New started has done its work

				// A control message, so that only it arriving means that nothing else
				// was sent, not that the endpoint is unreachable.
				require.NoError(t, s.c.Enqueue(analytics.Track{InstanceId: "control", DeploymentId: "control"}))
				require.NoError(t, s.Close())
			})

			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, []int{analytics.TypeTrack}, types)
		})
	}

	lock.Lock()
	instance = nil
	lock.Unlock()
}
