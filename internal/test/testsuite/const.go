package testsuite

import (
	"crypto/sha256"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
	"golang.org/x/text/language"
)

const (
	Password                 = "password"
	Secret                   = "0123456789101112"
	SubjectClaim             = "sub"
	TestDomain               = "example.com"
	ManagementCommandHold    = "hold release"
	ManagementCommandVersion = "version"
)

//nolint:gochecknoglobals
var (
	Cipher             = crypto.New(Secret)
	HashSecret         = sha256.Sum256([]byte(Secret))
	SupportedUILocales = []language.Tag{language.English}
)
