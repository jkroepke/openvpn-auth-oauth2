package types_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
)

func TestUserInfoGetSubject(t *testing.T) {
	t.Parallel()

	userInfo := types.UserInfo{Subject: "subject"}

	require.Equal(t, "subject", userInfo.GetSubject())
}
