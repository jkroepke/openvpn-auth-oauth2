package httphandler

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui"
)

func New(conf config.Config, oauth2 *oauth2.Client) (*http.ServeMux, error) {
	staticFs, err := fs.Sub(ui.Static, "assets")
	if err != nil {
		return nil, fmt.Errorf("failed to create static file system: %w", err)
	}

	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(fmt.Sprintf("GET %s/ready", basePath), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	mux.Handle(fmt.Sprintf("GET %s/assets/", basePath), http.StripPrefix(basePath+"/assets/", http.FileServerFS(staticFs)))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/start", basePath), noCacheHeaders(oauth2.OAuth2Start()))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/callback", basePath), noCacheHeaders(oauth2.OAuth2Callback()))

	return mux, nil
}

func noCacheHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}
