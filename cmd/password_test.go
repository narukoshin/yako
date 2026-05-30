package cmd

import (
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockClient struct {
	DoFunc func(url string) (*http.Response, error)
}

func (m *mockClient) Get(url string) (*http.Response, error) {
	return m.DoFunc(url)
}

func TestCheckHIBP_Found(t *testing.T) {
	pw := "P@ssw0rd!"
	hash := sha1.Sum([]byte(pw))
	hexHash := fmt.Sprintf("%X", hash)
	suffix := hexHash[5:]

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(suffix + ":42\nOTHERHASH:1\n"))
	}))
	defer server.Close()

	old := hibpClient
	hibpClient = &mockClient{DoFunc: func(url string) (*http.Response, error) {
		return http.Get(server.URL)
	}}
	defer func() { hibpClient = old }()

	var stderr strings.Builder
	oldStderr := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = oldStderr }()

	checkHIBP(pw)

	if stderr.String() == "" {
		t.Fatal("expected breach warning on stderr, got none")
	}
	if !strings.Contains(stderr.String(), "data breaches") {
		t.Errorf("expected breach warning, got: %s", stderr.String())
	}
}

func TestCheckHIBP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\n"))
	}))
	defer server.Close()

	old := hibpClient
	hibpClient = &mockClient{DoFunc: func(url string) (*http.Response, error) {
		return http.Get(server.URL)
	}}
	defer func() { hibpClient = old }()

	var stderr strings.Builder
	oldStderr := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = oldStderr }()

	checkHIBP("ThisPasswordIsNotInBreach123!")

	if stderr.String() != "" {
		t.Fatalf("expected no warning, got: %s", stderr.String())
	}
}

func TestCheckHIBP_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	old := hibpClient
	hibpClient = &mockClient{DoFunc: func(url string) (*http.Response, error) {
		return http.Get(server.URL)
	}}
	defer func() { hibpClient = old }()

	var stderr strings.Builder
	oldStderr := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = oldStderr }()

	checkHIBP("AnyPasswordHere1!")

	if stderr.String() != "" {
		t.Fatalf("expected no warning on server error, got: %s", stderr.String())
	}
}

func TestCheckHIBP_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte{})
	}))
	defer server.Close()

	old := hibpClient
	hibpClient = &mockClient{DoFunc: func(url string) (*http.Response, error) {
		return http.Get(server.URL)
	}}
	defer func() { hibpClient = old }()

	var stderr strings.Builder
	oldStderr := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = oldStderr }()

	checkHIBP("EmptyResponseTest1!")

	if stderr.String() != "" {
		t.Fatalf("expected no warning on empty response, got: %s", stderr.String())
	}
}

func TestCheckHIBP_RealAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real HIBP API test")
	}

	old := hibpClient
	hibpClient = &http.Client{Timeout: 10 * time.Second}
	defer func() { hibpClient = old }()

	t.Run("known breached password", func(t *testing.T) {
		var stderr strings.Builder
		oldStderr := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = oldStderr }()

		checkHIBP("password")

		if stderr.String() == "" {
			t.Fatal("expected breach warning for 'password', got none")
		}
		if !strings.Contains(stderr.String(), "data breaches") {
			t.Errorf("expected breach warning, got: %s", stderr.String())
		}
	})

	t.Run("random password not in breach", func(t *testing.T) {
		var stderr strings.Builder
		oldStderr := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = oldStderr }()

		checkHIBP("A9f8K2mP7xQ4vZ1wR3nL6jH5cB0sD8yE")

		if stderr.String() != "" {
			t.Fatalf("expected no warning for random password, got: %s", stderr.String())
		}
	})
}

func TestCheckHIBP_SuffixMatch(t *testing.T) {
	pw := "Password123!"
	hash := sha1.Sum([]byte(pw))
	hexHash := fmt.Sprintf("%X", hash)
	suffix := hexHash[5:]

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(suffix + ":999\n"))
	}))
	defer server.Close()

	old := hibpClient
	hibpClient = &mockClient{DoFunc: func(url string) (*http.Response, error) {
		return http.Get(server.URL)
	}}
	defer func() { hibpClient = old }()

	var stderr strings.Builder
	oldStderr := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = oldStderr }()

	checkHIBP(pw)

	if stderr.String() == "" {
		t.Fatal("expected breach warning when suffix matches, got none")
	}
}
