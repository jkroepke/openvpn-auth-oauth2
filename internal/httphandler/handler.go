package httphandler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ui/assets"
)

// New returns a ServeMux with all HTTP endpoints for the management listener.
//
// The handlers are mounted under the base path from conf.HTTP.BaseURL and
// register the following routes:
//   - GET <basePath>/ready           readiness probe responding with "OK".
//   - GET <basePath>/assets/*        serves custom static files, falling back to embedded ones.
//   - GET <basePath>/oauth2/start    initiates the OAuth2 login flow.
//   - GET <basePath>/oauth2/callback handles the OAuth2 redirect.
//
// All other paths respond with 404 via http.NotFoundHandler.
// The returned mux can be passed to an HTTP server directly.
// readyCheck is optional for existing test harnesses; production passes the
// OpenVPN client readiness callback.
func New(conf *config.Config, oAuth2Client *oauth2.Client, readyCheck ...func() bool) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	isReady := func() bool { return true }
	if len(readyCheck) != 0 && readyCheck[0] != nil {
		isReady = readyCheck[0]
	}

	mux := http.NewServeMux()
	if basePath != "" {
		mux.Handle("/", http.NotFoundHandler())
	}

	mux.Handle(fmt.Sprintf("GET %s/", basePath), noCacheHeaders(http.NotFoundHandler()))
	mux.Handle(fmt.Sprintf("GET %s/ready", basePath), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !isReady() {
			http.Error(w, "OpenVPN management connection is not ready", http.StatusServiceUnavailable)

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	assetsFS := overlayFS{upper: conf.HTTP.AssetPath, lower: assets.FS}
	mux.Handle(fmt.Sprintf("GET %s/assets/", basePath), securityHeaders(http.StripPrefix(basePath+"/assets/", http.FileServerFS(assetsFS))))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/start", basePath), noCacheHeaders(oAuth2Client.OAuth2Start()))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/callback", basePath), noCacheHeaders(oAuth2Client.OAuth2Callback()))
	mux.Handle(fmt.Sprintf("POST %s/oauth2/profile-submit", basePath), noCacheHeaders(oAuth2Client.OAuth2ProfileSubmit()))

	return mux
}

// securityHeaders sets defensive response headers. Pages set their content
// security policy in the HTML template; these headers cover what a meta tag
// cannot express and responses that are not HTML.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}

// noCacheHeaders sets the defensive response headers and forbids caching;
// the OAuth2 responses carry per-login state and error details.
func noCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		setSecurityHeaders(header)
		header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		header.Set("Pragma", "no-cache")
		header.Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

// setSecurityHeaders adds headers that stop browsers from sniffing content
// types, framing the login pages, or leaking the callback URL as a referrer.
func setSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "frame-ancestors 'none'")
}
