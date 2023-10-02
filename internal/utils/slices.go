package utils

import (
	"errors"
	"fmt"
)

var ErrCast = errors.New("unable to cast")

func CastToSlice[T any](tokenGroups any) ([]T, error) {
	tokenGroupsInterfaceList, ok := tokenGroups.([]any)
	if !ok {
		return nil, fmt.Errorf("%w input to []any", ErrCast)
	}

	tokenGroupsList := make([]T, len(tokenGroupsInterfaceList))

	for i, v := range tokenGroupsInterfaceList {
		tokenGroupsList[i], ok = v.(T)
		if !ok {
			return nil, fmt.Errorf("%w element", ErrCast)
		}
	}

	return tokenGroupsList, nil
}
