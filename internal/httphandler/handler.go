package httphandler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
)

// New returns a ServeMux with all HTTP endpoints for the management listener.
//
// The handlers are mounted under the base path from conf.HTTP.BaseURL and
// register the following routes:
//   - GET <basePath>/ready           readiness probe responding with "OK".
//   - GET <basePath>/assets/*        serves embedded or custom static files.
//   - GET <basePath>/oauth2/start    initiates the OAuth2 login flow.
//   - GET <basePath>/oauth2/callback handles the OAuth2 redirect.
// All other paths respond with 404 via http.NotFoundHandler.
// The returned mux can be passed to an HTTP server directly.

func New(conf config.Config, oAuth2Client *oauth2.Client) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	if basePath != "" {
		mux.Handle("/", http.NotFoundHandler())
	}

	mux.Handle(fmt.Sprintf("GET %s/", basePath), noCacheHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conf.HTTP.ShortURL && r.URL.Query().Has("s") {
			http.Redirect(w, r, fmt.Sprintf("%s/oauth2/start?state=%s", basePath, r.URL.Query().Get("s")), http.StatusFound)

			return
		}

		http.NotFound(w, r)
	})))
	mux.Handle(fmt.Sprintf("GET %s/ready", basePath), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	mux.Handle(fmt.Sprintf("GET %s/assets/", basePath), http.StripPrefix(basePath+"/assets/", http.FileServerFS(conf.HTTP.AssetPath)))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/start", basePath), noCacheHeaders(oAuth2Client.OAuth2Start()))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/callback", basePath), noCacheHeaders(oAuth2Client.OAuth2Callback()))

	return mux
}

func noCacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}
