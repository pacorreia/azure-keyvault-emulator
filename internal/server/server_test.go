package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("TEST_ENV_OR_DEFAULT", "value")
	if got := envOrDefault("TEST_ENV_OR_DEFAULT", "fallback"); got != "value" {
		t.Fatalf("unexpected value %q", got)
	}
	t.Setenv("TEST_ENV_OR_DEFAULT", "")
	if got := envOrDefault("TEST_ENV_OR_DEFAULT", "fallback"); got != "fallback" {
		t.Fatalf("unexpected fallback %q", got)
	}
	if got := envOrDefault("TEST_ENV_OR_DEFAULT_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("unexpected missing fallback %q", got)
	}
}

func TestGenerateSelfSignedCertificate(t *testing.T) {
	cert, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("expected certificate material")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "azure-keyvault-emulator" || len(leaf.DNSNames) == 0 {
		t.Fatalf("unexpected cert %+v", leaf)
	}

	oldRSA := serverRSAKeyGenerator
	serverRSAKeyGenerator = func(io.Reader, int) (*rsa.PrivateKey, error) { return nil, errors.New("boom") }
	if _, err := generateSelfSignedCertificate(); err == nil {
		t.Fatal("expected rsa error")
	}
	serverRSAKeyGenerator = oldRSA
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	serverRSAKeyGenerator = func(io.Reader, int) (*rsa.PrivateKey, error) { return key, nil }
	oldRandInt := serverRandInt
	serverRandInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, errors.New("boom") }
	if _, err := generateSelfSignedCertificate(); err == nil {
		t.Fatal("expected rand.Int error")
	}
	serverRandInt = oldRandInt
	oldCreate := serverCreateCertificate
	serverCreateCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if _, err := generateSelfSignedCertificate(); err == nil {
		t.Fatal("expected create certificate error")
	}
	serverCreateCertificate = oldCreate
	serverRSAKeyGenerator = oldRSA
}

func TestNewMux(t *testing.T) {
	if NewMux(store.New()) == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	called := false
	h := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusCreated {
		t.Fatalf("unexpected middleware result called=%v code=%d", called, rec.Code)
	}

	rec = httptest.NewRecorder()
	loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected default status %d", rec.Code)
	}
}

func TestRun(t *testing.T) {
	t.Run("graceful shutdown", func(t *testing.T) {
		t.Setenv("PORT", "0")
		t.Setenv("HTTPS_PORT", "0")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() { errCh <- Run(ctx, store.New()) }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not exit")
		}
	})

	t.Run("invalid https port", func(t *testing.T) {
		t.Setenv("PORT", "0")
		t.Setenv("HTTPS_PORT", "bad")
		if err := Run(context.Background(), store.New()); err == nil {
			t.Fatal("expected https listener error")
		}
	})

	t.Run("invalid http port", func(t *testing.T) {
		t.Setenv("PORT", "bad")
		t.Setenv("HTTPS_PORT", "0")
		if err := Run(context.Background(), store.New()); err == nil {
			t.Fatal("expected http listener error")
		}
	})

	t.Run("certificate generation failure", func(t *testing.T) {
		oldRSA := serverRSAKeyGenerator
		serverRSAKeyGenerator = func(io.Reader, int) (*rsa.PrivateKey, error) { return nil, errors.New("boom") }
		defer func() { serverRSAKeyGenerator = oldRSA }()
		t.Setenv("PORT", "0")
		t.Setenv("HTTPS_PORT", "0")
		if err := Run(context.Background(), store.New()); err == nil {
			t.Fatal("expected certificate generation failure")
		}
	})

	t.Run("tls listen failure", func(t *testing.T) {
		oldTLSListen := serverTLSListen
		serverTLSListen = func(string, string, *tls.Config) (net.Listener, error) { return nil, errors.New("boom") }
		defer func() { serverTLSListen = oldTLSListen }()
		t.Setenv("PORT", "0")
		t.Setenv("HTTPS_PORT", "0")
		if err := Run(context.Background(), store.New()); err == nil {
			t.Fatal("expected tls listen failure")
		}
	})
}
