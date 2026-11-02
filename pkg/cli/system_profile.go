// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// systemProfileView describes next-start policy, never a mutable candidate or
// the currently bound sockets. Address environment overrides remain separate.
func systemProfileView(saved *config.Config, strict bool) (*config.Config, config.TLSProfileFields) {
	effective, _ := config.ProjectProfile(saved, strict)
	var fields config.TLSProfileFields
	for _, field := range []struct {
		saved, effective *bool
		value            *bool
		source           *string
		overridden       **bool
	}{
		{saved.System.Mgmt.EnableHTTP, effective.System.Mgmt.EnableHTTP, &fields.HTTPEnabled, &fields.HTTPEnabledSource, &fields.HTTPEnabledSaved},
		{saved.System.Mgmt.EnableHTTPS, effective.System.Mgmt.EnableHTTPS, &fields.HTTPSEnabled, &fields.HTTPSEnabledSource, &fields.HTTPSEnabledSaved},
		{saved.System.Mgmt.EnableHSTS, effective.System.Mgmt.EnableHSTS, &fields.HSTSEnabled, &fields.HSTSEnabledSource, &fields.HSTSEnabledSaved},
	} {
		*field.value = boolDefault(field.effective, true)
		*field.source = "default"
		if field.saved != nil {
			*field.source = "config"
		}
		if before := boolDefault(field.saved, true); before != *field.value {
			*field.source = "profile"
			*field.overridden = &before
		}
	}
	return effective, fields
}

func printSystemProfileTLS(out io.Writer, fields config.TLSProfileFields) {
	for _, field := range []struct {
		name   string
		value  bool
		source string
		saved  *bool
	}{
		{"http_enabled", fields.HTTPEnabled, fields.HTTPEnabledSource, fields.HTTPEnabledSaved},
		{"https_enabled", fields.HTTPSEnabled, fields.HTTPSEnabledSource, fields.HTTPSEnabledSaved},
		{"hsts", fields.HSTSEnabled, fields.HSTSEnabledSource, fields.HSTSEnabledSaved},
	} {
		fmt.Fprintf(out, "mgmt.%s: %s\nmgmt.%s_source: %s\n", field.name, yesNoStr(field.value), field.name, field.source)
		if field.saved != nil {
			fmt.Fprintf(out, "mgmt.%s_saved: %s\n", field.name, yesNoStr(*field.saved))
		}
	}
}
