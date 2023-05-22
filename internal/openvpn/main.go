package openvpn

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func CheckEnv() error {
	if os.Getenv("script_type") != SupportedScriptType {
		return fmt.Errorf("only script_type %s is supported. got: %s", SupportedScriptType, os.Getenv("script_type"))
	}

	if _, ok := os.LookupEnv(EnvVarAuthFailedReason); !ok {
		return fmt.Errorf("missing env variable %s", EnvVarAuthFailedReason)
	}

	if _, ok := os.LookupEnv(EnvVarAuthPending); !ok {
		return fmt.Errorf("missing env variable %s", EnvVarAuthPending)
	}

	if _, ok := os.LookupEnv(EnvVarAuthControlFile); !ok {
		return fmt.Errorf("missing env variable %s", EnvVarAuthControlFile)
	}

	return nil
}

func AuthFailedReason(reason string) {
	reason = strings.TrimSpace(reason)

	if err := WriteAuthFailedReason(reason); err != nil {
		log.Println(err)
	}

	if err := WriteAuthControl(ControlCodeAuthFailed); err != nil {
		log.Println(err)
	}

	log.Fatal(reason)
}

func WriteAuthFailedReason(reason string) error {
	return os.WriteFile(os.Getenv(EnvVarAuthFailedReason), []byte(reason), 0600)
}

func WriteAuthControl(status int) error {
	return os.WriteFile(os.Getenv(EnvVarAuthControlFile), []byte(strconv.Itoa(status)), 0600)
}

func WriteAuthPending(timeout int, method, extra string) error {
	content := fmt.Sprintf("%d\n%s\n%s\n", timeout, method, extra)
	return os.WriteFile(os.Getenv(EnvVarAuthPending), []byte(content), 0600)
}

func GetClientCommonName() (string, error) {
	if commonName, ok := os.LookupEnv(EnvVarCommonName); ok {
		return commonName, nil
	}

	return "", fmt.Errorf("can't find %s environment variable", EnvVarCommonName)
}

func ValidateWebAuthCompatibility() error {
	if ivSso, ok := os.LookupEnv(IvSso); !ok {
		return fmt.Errorf("can't find IV_SSO environment variable. Client doesn't support SSO login")
	} else if !strings.Contains(ivSso, "webauth") {
		return fmt.Errorf("client doesn't support 'webauth'")
	}

	return nil
}
