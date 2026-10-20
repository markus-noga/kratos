// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/defense"
	"github.com/ory/kratos/defense/defensetest"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/pkg"
	"github.com/ory/x/configx"
)

// The known device cookie follows the attack defense unless forced.
func TestKnownDeviceCookieFollowsTheDefense(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		setting any // defense.known_device_cookie.enabled; nil: unset
		uses    bool
		noop    bool
		want    bool
	}{
		"auto with the default no-op defense":   {setting: nil, noop: true, want: false},
		"unset with a defense that uses it":     {setting: nil, uses: true, want: true},
		"auto with a defense that does not":     {setting: "auto", uses: false, want: false},
		"auto with a defense that uses it":      {setting: "auto", uses: true, want: true},
		"false wins over a defense that uses":   {setting: false, uses: true, want: false},
		"true wins over the default no-op":      {setting: true, noop: true, want: true},
		"true with a defense that does not":     {setting: "true", uses: false, want: true},
		"false with a defense that does not":    {setting: "false", uses: false, want: false},
		"false with the default no-op defense":  {setting: false, noop: true, want: false},
		"auto, a defense that uses it, as text": {setting: "AUTO", uses: true, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var opts []configx.OptionModifier
			if tc.setting != nil {
				opts = append(opts, configx.WithValue(config.ViperKeyKnownDeviceCookieEnabled, tc.setting))
			}
			_, reg := pkg.NewFastRegistryWithMocks(t, opts...)
			if !tc.noop {
				rec := new(defensetest.Recorder)
				rec.UseKnownDeviceVerdict(tc.uses)
				reg.WithDefense(rec)
			} else {
				assert.IsType(t, defense.Noop{}, reg.Defense())
			}
			assert.Equal(t, tc.want, reg.KnownDeviceCookie(t.Context()) != nil)
			assert.Equal(t, tc.want, reg.KnownDeviceCookieEnabled(t.Context()), "says the same as the codec")
		})
	}

	t.Run("the answer follows the defense while the process runs", func(t *testing.T) {
		t.Parallel()
		_, reg := pkg.NewFastRegistryWithMocks(t)
		rec := new(defensetest.Recorder)
		reg.WithDefense(rec)
		assert.Nil(t, reg.KnownDeviceCookie(t.Context()))
		rec.UseKnownDeviceVerdict(true)
		assert.NotNil(t, reg.KnownDeviceCookie(t.Context()))
		rec.UseKnownDeviceVerdict(false)
		assert.Nil(t, reg.KnownDeviceCookie(t.Context()))
	})
}
