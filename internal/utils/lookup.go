package utils

import (
	"fmt"
	"os/user"
	"strconv"
)

// LookupGroup returns the numeric gid for groupName. It accepts either a
// numeric string or a system group name and returns an error if the group
// cannot be resolved.
func LookupGroup(groupName string) (int, error) {
	var (
		gid   int
		group *user.Group
		err   error
	)

	gid, err = strconv.Atoi(groupName)
	if err == nil {
		return gid, nil
	}

	group, err = user.LookupGroup(groupName)
	if err != nil {
		return 0, fmt.Errorf("error lookup group: %w", err)
	}

	gid, err = strconv.Atoi(group.Gid)
	if err != nil {
		return 0, fmt.Errorf("error convert group id: %w", err)
	}

	return gid, nil
}
