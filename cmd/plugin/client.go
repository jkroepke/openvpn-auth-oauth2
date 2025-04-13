//go:build linux

package main

import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

type Client struct {
	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	IpAddr               string
	IpPort               string
	CommonName           string
	Username             string
}

func NewClient(pointer unsafe.Pointer) Client {
	envp := (*[1 << 28]*C.char)(pointer)[:128:128]
	var client Client

	for i := 0; envp[i] != nil; i++ {
		envParts := strings.SplitN(C.GoString(envp[i]), "=", 2)
		switch envParts[0] {
		case "auth_failed_reason_file":
			client.AuthFailedReasonFile = envParts[1]
		case "auth_pending_file":
			client.AuthPendingFile = envParts[1]
		case "auth_control_file":
			client.AuthControlFile = envParts[1]
		case "untrusted_ip":
			client.IpAddr = envParts[1]
		case "untrusted_ip6":
			client.IpAddr = envParts[1]
		case "untrusted_port":
			client.IpPort = envParts[1]
		case "common_name":
			client.CommonName = envParts[1]
		case "username":
			client.Username = envParts[1]
		default:
			continue
		}
	}

	return client
}

func (c *Client) String() string {
	sb := strings.Builder{}
	sb.WriteString(">CLIENT:CONNECT,0,1")
	sb.WriteString("\r\n>CLIENT:ENV,username=")
	sb.WriteString(c.Username)
	if strings.Contains()
	sb.WriteString("\r\n>CLIENT:ENV,untrusted_ip=")
	sb.WriteString("\r\n>CLIENT:ENV,untrusted_port=")
	sb.WriteString(">CLIENT:ENV,END")


	fmt.Sprintf(">CLIENT:CONNECT,0,1\n>CLIENT:ENV,username=%s\n>CLIENT:ENV,untrusted_ip=%s\n>CLIENT:ENV,untrusted_port=%s\n>CLIENT:ENV,END",
		,)
}
