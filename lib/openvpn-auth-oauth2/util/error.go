package util

import (
	"strings"

	"solod.dev/so/errors"
	"solod.dev/so/fmt"
)

func Errorf(format string, args ...any) error {
	bufLen := len(format)
	for _, arg := range args {
		switch t := arg.(type) {
		case error:
			bufLen += len(t.Error())
		case string:
			bufLen += len(t)
		case int, int32, int64, uint, uint32, uint64:
			bufLen += 4
		default:
			bufLen++
		}
	}

	return errors.New(fmt.Sprintf(fmt.NewBuffer(bufLen), strings.ReplaceAll(format, "%w", "%s"), args...))
}
