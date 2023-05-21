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

	WriteAuthFailedReason(reason)
	WriteAuthControl(ControlCodeAuthFailed)
	log.Fatalf("%s:%s [%s] openvpn-auth-azure-ad: %s",
		os.Getenv(EnvVarClientIp),
		os.Getenv(EnvVarClientPort),
		os.Getenv(EnvVarCommonName),
		reason,
	)
}

func WriteAuthFailedReason(reason string) {
	err := os.WriteFile(os.Getenv(EnvVarAuthFailedReason), []byte(reason), 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func WriteAuthControl(status int) {
	err := os.WriteFile(os.Getenv(EnvVarAuthControlFile), []byte(strconv.Itoa(status)), 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func WriteAuthPending(timeout int, method, extra string) error {
	content := fmt.Sprintf("%d\n%s\n%s\n", timeout, method, extra)
	err := os.WriteFile(os.Getenv(EnvVarAuthPending), []byte(content), 0600)
	if err != nil {
		return err
	}
	return nil
}
