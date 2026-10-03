package management

import (
	"testing"
	"time"
)

// The plugin must not reject an initial authentication attempt before the
// daemon's single-request 30-second OAuth2 HTTP timeout can elapse.
func TestInitialAuthResponseTimeoutCoversOAuth2Request(t *testing.T) {
	t.Parallel()

	if initialAuthResponseTimeout <= 30*time.Second {
		t.Fatalf("initial auth response timeout %s must exceed the outbound OAuth2 request timeout", initialAuthResponseTimeout)
	}
}
