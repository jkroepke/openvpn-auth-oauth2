package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider/azuread"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider/generic"
	"golang.org/x/exp/slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
)

const (
	envVarPendingAuth = "__OPENVPN_AUTH_OAUTH2__START_PENDING_AUTH"
)

var version = "unknown"

func main() {
	log.SetPrefix(
		fmt.Sprintf("%s:%s [%s] openvpn-auth-oauth2: ",
			os.Getenv(openvpn.EnvVarClientIp),
			os.Getenv(openvpn.EnvVarClientPort),
			os.Getenv(openvpn.EnvVarCommonName),
		),
	)

	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		os.Exit(0)
	}

	if err := openvpn.CheckEnv(); err != nil {
		log.Fatalf(err.Error())
	}

	if len(os.Args) != 2 {
		log.Fatalf("Invalid count of CLI parameters. Usage: %s credential-file", os.Args[0])
	}

	conf, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Can't read config: %v", err)
	}

	if commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName); ok && slices.Contains(conf.OAuthOpenVpnBypassAuthCn, commonName) {
		log.Printf("skip azure ad authentification")
	}

	var authProvider provider.Provider

	switch conf.Provider {
	case config.ProviderGeneric:
		authProvider, err = generic.New()
		if err != nil {
			log.Fatal(err)
		}
	case config.ProviderAzureAd:
		authProvider, err = azuread.New()
		if err != nil {
			log.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.AuthTimeout)*time.Second)
	defer cancel()

	if _, ok := os.LookupEnv(envVarPendingAuth); ok {
		deviceCodeUrl, err := authProvider.StartAuthentication(ctx)
		if err != nil {
			openvpn.AuthFailedReason(err.Error())
		}

		fmt.Println(deviceCodeUrl)
	} else {
		if err := authProvider.ValidateAuthentication(ctx); err != nil {
			log.Fatal(err)
		}

		os.Exit(openvpn.ExitCodeAuthPending)
	}
}

func startPendingAuthentication(conf config.Config) error {
	deviceCode, err := startDeviceCodeAuthProcess()

	if err != nil {
		return fmt.Errorf("error starting pending auth process: %v", err)
	}

	if ivSso, ok := os.LookupEnv(openvpn.IvSso); !ok {
		return fmt.Errorf("can't find IV_SSO environment variable. Client doesn't support SSO login")
	} else if !strings.Contains(ivSso, "webauth") {
		return fmt.Errorf("client doesn't support 'webauth'")
	}

	openUrl := fmt.Sprintf("WEB_AUTH::%s?code=%s", conf.UrlHelper.String(), deviceCode)
	err = openvpn.WriteAuthPending(conf.AuthTimeout, "webauth", openUrl)

	if err != nil {
		return fmt.Errorf("error writing content to auth pending file: %v", err)
	}

	return nil
}

func startDeviceCodeAuthProcess() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(cmd.Environ(), envVarPendingAuth+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Scan()
	deviceCode := scanner.Text()

	if strings.TrimSpace(deviceCode) == "" {
		return "", fmt.Errorf("unable to gain device code. Check server logs")
	}

	if err := stdout.Close(); err != nil {
		return "", err
	}

	return deviceCode, nil
}
