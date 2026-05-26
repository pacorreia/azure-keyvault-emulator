package server

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/auth"
	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/handler"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
	"github.com/pacorreia/azure-keyvault-emulator/internal/web"
)

var (
	serverGenerateTLSCertificate = kvcrypto.GenerateTLSCertificate
	serverTLSListen              = tls.Listen
	serverNetListen              = net.Listen
)

// NewMux creates the HTTP mux for the Azure Key Vault emulator API only.
// Existing callers (including tests) use this signature unchanged.
func NewMux(s store.Storer) http.Handler {
	return NewMuxWithAuth(s, nil)
}

// NewMuxWithAuth creates the HTTP mux, optionally mounting the web UI.
// When a is non-nil the setup/login/dashboard UI is available at /ui/, and
// the main Key Vault API handler uses the same encrypted store so
// encryption-at-rest applies to all write paths.
func NewMuxWithAuth(s store.Storer, a *auth.Service) http.Handler {
	mux := http.NewServeMux()
	kvStore := s
	if a != nil {
		webHandler := web.New(a, s)
		webHandler.Register(mux)
		// Use the web handler's encrypted store so the KV API handler also
		// encrypts/decrypts secret values transparently.
		kvStore = webHandler.Store()
	}
	h := handler.New(kvStore)
	h.Register(mux)
	return loggingMiddleware(mux)
}

func Run(ctx context.Context, s store.Storer) error {
	return RunWithAuth(ctx, s, nil)
}

// RunWithAuth starts HTTP and HTTPS servers. When a is non-nil the web UI is enabled.
func RunWithAuth(ctx context.Context, s store.Storer, a *auth.Service) error {
	httpPort := envOrDefault("PORT", "8080")
	httpsPort := envOrDefault("HTTPS_PORT", "8443")
	handler := NewMuxWithAuth(s, a)

	httpServer := &http.Server{Addr: ":" + httpPort, Handler: handler}
	httpsServer := &http.Server{Addr: ":" + httpsPort, Handler: handler}

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		return err
	}
	httpsListener, err := serverTLSListen("tcp", httpsServer.Addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	httpListener, err := serverNetListen("tcp", httpServer.Addr)
	if err != nil {
		_ = httpsListener.Close()
		return err
	}

	log.Printf("azure-keyvault-emulator listening on http://0.0.0.0:%s and https://0.0.0.0:%s", httpPort, httpsPort)

	errCh := make(chan error, 2)
	go func() { errCh <- httpServer.Serve(httpListener) }()
	go func() { errCh <- httpsServer.Serve(httpsListener) }()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		_ = httpsServer.Shutdown(shutdownCtx)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.RequestURI(), rw.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func generateSelfSignedCertificate() (tls.Certificate, error) {
	return serverGenerateTLSCertificate("azure-keyvault-emulator", []string{"localhost", "emulator"})
}
