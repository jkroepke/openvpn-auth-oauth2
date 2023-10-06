package testutils

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

var mu = sync.Mutex{} //nolint:gochecknoglobals

func SendLine(t *testing.T, conn net.Conn, msg string) {
	t.Helper()

	_, err := fmt.Fprint(conn, msg)
	assert.NoError(t, err)
}

func ReadLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	assert.NoError(t, err)

	return strings.TrimSpace(line)
}

func SetupResourceServer(clientListener net.Listener) (*httptest.Server, config.OAuth2Client, error) {
	mu.Lock()
	storage.RegisterClients(storage.WebClient(clientListener.Addr().String(), "SECRET", fmt.Sprintf("http://%s/oauth2/callback", clientListener.Addr().String())))
	mu.Unlock()

	opStorage := storage.NewStorage(storage.NewUserStore("http://localhost"))
	opConfig := &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
	}

	opProvider, err := op.NewDynamicOpenIDProvider("", opConfig, opStorage,
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, config.OAuth2Client{}, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", opProvider.HttpHandler())
	mux.Handle("/login/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = opStorage.CheckUsernamePassword("test-user@localhost", "verysecure", r.FormValue("authRequestID"))
		http.Redirect(w, r, op.AuthCallbackURL(opProvider)(r.Context(), r.FormValue("authRequestID")), http.StatusFound)
	}))

	return httptest.NewServer(mux), config.OAuth2Client{ID: clientListener.Addr().String(), Secret: "SECRET"}, err
}
