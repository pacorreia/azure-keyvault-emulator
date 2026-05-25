package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pacorreia/azure-keyvault-emulator/internal/handler"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func NewMux(s *store.Store) http.Handler {
	mux := http.NewServeMux()
	h := handler.New(s)
	h.Register(mux)
	return loggingMiddleware(mux)
}

func Run(ctx context.Context, s *store.Store) error {
	httpPort := envOrDefault("PORT", "8080")
	httpsPort := envOrDefault("HTTPS_PORT", "8443")
	handler := NewMux(s)

	httpServer := &http.Server{Addr: ":" + httpPort, Handler: handler}
	httpsServer := &http.Server{Addr: ":" + httpsPort, Handler: handler}

	cert, err := generateSelfSignedCertificate()
	if err != nil {
		return err
	}
	httpsListener, err := tls.Listen("tcp", httpsServer.Addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	httpListener, err := net.Listen("tcp", httpServer.Addr)
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "azure-keyvault-emulator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "emulator"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
