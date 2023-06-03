package management

import (
	"log"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/lib/management/config"
)

func Run() {
	_, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Can't read config: %v", err)
	}
}
