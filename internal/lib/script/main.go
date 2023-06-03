package script

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

	commonConfig "github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/lib/script/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider/azuread"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/provider/generic"
	"golang.org/x/exp/slices"
)

const (
	envVarPendingAuth = "__OPENVPN_AUTH_OAUTH2__START_PENDING_AUTH"
)

func Run() {
	log.SetPrefix(
		fmt.Sprintf("%s:%s [%s] openvpn-auth-oauth2: ",
			os.Getenv(openvpn.EnvVarClientIp),
			os.Getenv(openvpn.EnvVarClientPort),
			os.Getenv(openvpn.EnvVarCommonName),
		),
	)

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

	if commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName); ok && slices.Contains(conf.CnBypassAuth, commonName) {
		log.Printf("skip azure ad authentification")
	}

	if err := openvpn.ValidateWebAuthCompatibility(); err != nil {
		log.Fatal(err)
	}

	if _, ok := os.LookupEnv(envVarPendingAuth); ok {
		if err := startDeviceCodeAuthentication(conf); err != nil {
			openvpn.AuthFailedReason(err.Error())
		}
	} else {
		if err := startPendingAuthentication(conf); err != nil {
			log.Fatal(err)
		}

		os.Exit(openvpn.ExitCodeAuthPending)
	}

	os.Exit(0)
}

func startDeviceCodeAuthentication(conf config.Config) error {
	authProvider, err := getAuthProvider(conf)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.AuthTimeout)*time.Second)
	defer cancel()

	deviceCodeResponse, err := authProvider.StartDeviceAuthorization(ctx)
	if err != nil {
		return err
	}

	openUrl := deviceCodeResponse.VerificationURIComplete

	if openUrl != "" {
		openUrl = fmt.Sprintf("%s?url=%s&code=%s", conf.UrlHelper.String(), deviceCodeResponse.VerificationURI, deviceCodeResponse.UserCode)
	}

	fmt.Println(openUrl)

	err = authProvider.ValidateDeviceAuthorization(ctx)
	if err != nil {
		return err
	}

	return openvpn.WriteAuthControl(openvpn.ControlCodeAuthSuccess)
}

func getAuthProvider(conf config.Config) (provider.Provider, error) {
	switch conf.Provider {
	case commonConfig.ProviderGeneric:
		return generic.New()
	case commonConfig.ProviderAzureAd:
		return azuread.New()
	}

	return nil, fmt.Errorf("unknown provider %s", conf.Provider)
}

func startPendingAuthentication(conf config.Config) error {
	verificationUrl, err := startDeviceCodeAuthProcess()
	if err != nil {
		return fmt.Errorf("error starting pending auth process: %v", err)
	}

	if err = openvpn.WriteAuthPending(conf.AuthTimeout, "webauth", fmt.Sprintf("WEB_AUTH::%s", verificationUrl)); err != nil {
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
