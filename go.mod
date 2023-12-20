module github.com/jkroepke/openvpn-auth-oauth2

go 1.21

require (
	github.com/knadh/koanf/parsers/yaml v0.1.0
	github.com/knadh/koanf/providers/basicflag v1.0.0
	github.com/knadh/koanf/providers/env v0.1.0
	github.com/knadh/koanf/providers/file v0.1.0
	github.com/knadh/koanf/providers/structs v0.1.0
	github.com/knadh/koanf/v2 v2.0.1
	github.com/madflojo/testcerts v1.1.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/stretchr/testify v1.8.4
	github.com/zitadel/logging v0.5.0
	github.com/zitadel/oidc/v3 v3.8.0
	golang.org/x/exp v0.0.0-20231219180239-dc181d75b848
	golang.org/x/oauth2 v0.15.0
	golang.org/x/text v0.14.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-chi/chi/v5 v5.0.11 // indirect
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/muhlemmer/httpforwarded v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/cors v1.10.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/zitadel/schema v1.3.0 // indirect
	go.opentelemetry.io/otel v1.21.0 // indirect
	go.opentelemetry.io/otel/metric v1.21.0 // indirect
	go.opentelemetry.io/otel/trace v1.21.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/mitchellh/mapstructure v1.5.0 => github.com/go-viper/mapstructure v1.6.0
	github.com/zitadel/oidc/v3 => github.com/jkroepke/oidc/v3 v3.0.0-20231219101841-010f41eefa80
)
