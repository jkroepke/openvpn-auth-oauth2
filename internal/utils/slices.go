package utils

func CastToSlice[T any](tokenGroups any) []T {
	tokenGroupsInterfaceList := tokenGroups.([]any)
	tokenGroupsList := make([]T, len(tokenGroupsInterfaceList))
	for i, v := range tokenGroupsInterfaceList {
		tokenGroupsList[i] = v.(T)
	}
	return tokenGroupsList
}
