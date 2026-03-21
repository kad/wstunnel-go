package main

import (
	"testing"

	"github.com/kad/wstunnel-go/pkg/client"
	"github.com/kad/wstunnel-go/pkg/server"
)

func TestMergeClientConfigIncludesJWTSecret(t *testing.T) {
	dst := &client.Config{}
	src := &client.Config{
		ServerURL: "ws://example.com",
		JWTSecret: "from-config",
	}

	mergeClientConfig(dst, src)

	if dst.ServerURL != src.ServerURL {
		t.Fatalf("ServerURL = %q, want %q", dst.ServerURL, src.ServerURL)
	}
	if dst.JWTSecret != src.JWTSecret {
		t.Fatalf("JWTSecret = %q, want %q", dst.JWTSecret, src.JWTSecret)
	}
}

func TestMergeServerConfigIncludesJWTFields(t *testing.T) {
	dst := &server.Config{}
	src := &server.Config{
		ListenAddr:              "ws://127.0.0.1:8080",
		JWTSecret:               "from-config",
		InsecureNoJWTValidation: true,
	}

	mergeServerConfig(dst, src)

	if dst.ListenAddr != src.ListenAddr {
		t.Fatalf("ListenAddr = %q, want %q", dst.ListenAddr, src.ListenAddr)
	}
	if dst.JWTSecret != src.JWTSecret {
		t.Fatalf("JWTSecret = %q, want %q", dst.JWTSecret, src.JWTSecret)
	}
	if !dst.InsecureNoJWTValidation {
		t.Fatal("InsecureNoJWTValidation was not merged from config")
	}
}
