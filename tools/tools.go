//go:build tools

package tools

//goland:noinspection ALL
import (
	_ "github.com/bombsimon/wsl/v4/cmd/wsl"
	_ "github.com/catenacyber/perfsprint"
	_ "github.com/daixiang0/gci"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/tetafro/godot/cmd/godot"
	_ "golang.org/x/tools/cmd/goimports"
	_ "mvdan.cc/gofumpt"
)
