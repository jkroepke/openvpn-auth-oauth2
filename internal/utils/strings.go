package utils

import "strings"

// StringConcat concatenates all provided strings and returns the result.
// It avoids intermediate allocations by using a strings.Builder.
func StringConcat(strs ...string) string {
	var sb strings.Builder
	for _, str := range strs {
		sb.WriteString(str)
	}

	return sb.String()
}
