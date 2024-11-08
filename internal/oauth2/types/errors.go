package types

import "errors"

var ErrNoRefreshToken = errors.New("no refresh token received from provider")
