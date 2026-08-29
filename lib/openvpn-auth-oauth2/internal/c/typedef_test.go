//go:build (darwin || linux || openbsd || freebsd) && cgo

package c_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/c"
)

func TestOpenVPNPluginStringList_Add(t *testing.T) {
	t.Parallel()

	list, err := c.NewOpenVPNPluginStringList()
	if err != nil {
		t.Fatalf("NewOpenVPNPluginStringList() error = %v", err)
	}

	if err := list.Add("first", "one"); err != nil {
		t.Fatalf("Add() first item error = %v", err)
	}

	if err := list.Add("second", "two"); err != nil {
		t.Fatalf("Add() second item error = %v", err)
	}

	if actual := c.GoString(list.Name); actual != "first" {
		t.Errorf("first item name = %q, want %q", actual, "first")
	}

	if actual := c.GoString(list.Value); actual != "one" {
		t.Errorf("first item value = %q, want %q", actual, "one")
	}

	if list.Next == nil {
		t.Fatal("second item is nil")
	}

	if actual := c.GoString(list.Next.Name); actual != "second" {
		t.Errorf("second item name = %q, want %q", actual, "second")
	}

	if actual := c.GoString(list.Next.Value); actual != "two" {
		t.Errorf("second item value = %q, want %q", actual, "two")
	}

	if list.Next.Next != nil {
		t.Error("second item next is not nil")
	}
}

func TestOpenVPNPluginStringList_AddNilReceiver(t *testing.T) {
	t.Parallel()

	var list *c.OpenVPNPluginStringList

	if err := list.Add("name", "value"); err == nil {
		t.Fatal("Add() error = nil, want an error")
	}
}
