package httpapi

import "strings"

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}
