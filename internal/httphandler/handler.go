package httphandler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
)

func New(conf config.Config, oAuth2Client *oauth2.Client) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
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
