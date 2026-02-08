package config

import (
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
)

const CommonNameModeOmitValue = "-"

// String returns the string representation of the common name mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) MarshalText() ([]byte, error) {
	switch s {
	case CommonNameModePlain:
		return []byte("plain"), nil
	case CommonNameModeOmit:
		return []byte("omit"), nil
	default:
		return nil, fmt.Errorf("unknown identifier %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OpenVPNCommonNameMode) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "plain":
		*s = CommonNameModePlain
	case "omit":
		*s = CommonNameModeOmit
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}

type OAuth2AuthStyle oauth2.AuthStyle

// String returns the string representation of the auth style.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// AuthStyle converts the wrapper type to [oauth2.AuthStyle].
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) AuthStyle() oauth2.AuthStyle {
	return oauth2.AuthStyle(s)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2AuthStyle(oauth2.AuthStyleAutoDetect):
		return []byte("AuthStyleAutoDetect"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInParams):
		return []byte("AuthStyleInParams"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInHeader):
		return []byte("AuthStyleInHeader"), nil
	default:
		return nil, fmt.Errorf("unknown auth-style: %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2AuthStyle) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "authstyleautodetect":
		*s = OAuth2AuthStyle(oauth2.AuthStyleAutoDetect)
	case "authstyleinparams":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInParams)
	case "authstyleinheader":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInHeader)
	default:
		return fmt.Errorf("unknown auth-style: %s", text)
	}

	return nil
}

type OAuth2RefreshNonce int

const (
	OAuth2RefreshNonceAuto OAuth2RefreshNonce = iota
	OAuth2RefreshNonceEmpty
	OAuth2RefreshNonceEqual
)

// String returns the string representation of the refresh nonce mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2RefreshNonceAuto:
		return []byte("auto"), nil
	case OAuth2RefreshNonceEmpty:
		return []byte("empty"), nil
	case OAuth2RefreshNonceEqual:
		return []byte("equal"), nil
	default:
		return nil, fmt.Errorf("unknown refresh-nonce %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2RefreshNonce) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "auto":
		*s = OAuth2RefreshNonceAuto
	case "empty":
		*s = OAuth2RefreshNonceEmpty
	case "equal":
		*s = OAuth2RefreshNonceEqual
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}
