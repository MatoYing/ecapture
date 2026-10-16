// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestNewProbe(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	if probe == nil {
		t.Fatal("NewProbe() returned nil")
		return
	}
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_Initialize(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	cfg := NewConfig()
	cfg.OpensslPath = "/nonexistent/path/libssl.so.1.1"

	// Test that Initialize returns an error when the openssl path does not exist
	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() with non-existent openssl path should return error")
	}
}

func TestProbe_Initialize_InvalidConfig(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Use a non-existent path to ensure config validation fails reliably
	cfg := NewConfig()
	cfg.OpensslPath = "/nonexistent/path/libssl.so.1.1"

	ctx := context.Background()

	err = probe.Initialize(ctx, cfg)
	if err == nil {
		t.Error("Initialize() with invalid config should return error")
	}
}

func TestProbe_SetOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	buf := &bytes.Buffer{}
	probe.SetOutput(buf)

	if probe.output != buf {
		t.Error("SetOutput() did not set output correctly")
	}
}

func TestProbe_Close(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Close without initializing - should handle gracefully
	// We can't test this directly because BaseProbe requires initialization
	// Just test that the probe was created successfully
	if probe == nil {
		t.Error("Probe should not be nil")
	}
}

func TestProbe_Events(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	events := probe.Events()
	// Should return empty slice for stub implementation
	if events == nil {
		t.Error("Events() returned nil")
	}
}

func TestProbe_Lifecycle(t *testing.T) {
	// Test basic lifecycle without full initialization
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Set output
	var buf bytes.Buffer
	probe.SetOutput(&buf)

	// Just test that basic methods work
	if probe.Name() != "OpenSSL" {
		t.Errorf("Name() = %v, want 'OpenSSL'", probe.Name())
	}
}

func TestProbe_WithRealOutput(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() failed: %v", err)
	}

	// Test with a real writer
	var buf bytes.Buffer
	probe.SetOutput(io.Writer(&buf))

	if probe.output == nil {
		t.Error("Output writer not set")
	}
}

func TestSetupManagerTextMbedTLSFileOffsets(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	cfg := NewConfig()
	cfg.OpensslPath = "/system/lib64/libcysec.syan.so"
	probe.config = cfg

	if err := probe.setupManagerText(); err != nil {
		t.Fatalf("setupManagerText() error = %v", err)
	}

	want := map[string]struct {
		name   string
		offset uint64
	}{
		"uprobe/SSL_read":     {"mbedtls_ssl_read", mbedtlsSSLReadFileOffset},
		"uretprobe/SSL_read":  {"mbedtls_ssl_read", mbedtlsSSLReadFileOffset},
		"uprobe/SSL_write":    {"mbedtls_ssl_write", mbedtlsSSLWriteFileOffset},
		"uretprobe/SSL_write": {"mbedtls_ssl_write", mbedtlsSSLWriteFileOffset},
	}
	seen := map[string]int{}
	var hasConnect bool
	for _, pr := range probe.bpfManager.Probes {
		switch pr.AttachToFuncName {
		case "SSL_read", "SSL_write", "SSL_set_fd", "SSL_set_rfd", "SSL_set_wfd",
			"cysec_tls_client_read", "cysec_tls_client_write":
			t.Errorf("unexpected hook %s", pr.AttachToFuncName)
		case "__sys_connect":
			hasConnect = true
		}
		expect, ok := want[pr.Section]
		if !ok {
			continue
		}
		seen[pr.Section]++
		if pr.AttachToFuncName != expect.name || pr.UAddress != expect.offset || pr.BinaryPath != cfg.OpensslPath {
			t.Errorf("%s hook = %s %#x %s", pr.Section, pr.AttachToFuncName, pr.UAddress, pr.BinaryPath)
		}
	}
	for section := range want {
		if seen[section] != 1 {
			t.Errorf("%s attached %d times", section, seen[section])
		}
	}
	if !hasConnect {
		t.Error("connect kprobe was removed")
	}
	if mbedtlsSSLReadFileOffset != 0x76db0 || mbedtlsSSLWriteFileOffset != 0x770fc {
		t.Fatalf("file offsets changed: read %#x write %#x", mbedtlsSSLReadFileOffset, mbedtlsSSLWriteFileOffset)
	}
}
