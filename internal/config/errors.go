package config

import "errors"

var (
	ErrRequired                            = errors.New("required")
	ErrCommonNameEmailRegexpRequiresEmail  = errors.New("oauth2.validate.common-name-email-regexp requires oauth2.validate.common-name to be 'email'")
	ErrCommonNameEmailRegexpPatternMissing = errors.New("oauth2.validate.common-name-email-regexp.pattern is required")
	ErrCommonNameEmailRegexpReplaceMissing = errors.New("oauth2.validate.common-name-email-regexp.replacement is required")
	ErrCommonNameEmailRegexpInvalidPattern = errors.New("oauth2.validate.common-name-email-regexp.pattern is not a valid regexp")
)
