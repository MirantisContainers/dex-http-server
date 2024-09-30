package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/rs/zerolog/log"
)

const (
	caCertFile = "ca.crt"
	certFile   = "tls.crt"
	keyFile    = "tls.key"
)

// LoadTLSConfig loads the TLS configuration from the provided directory
func LoadTLSConfig(certDir string) (*tls.Config, error) {
	log.Info().Msgf("Loading TLS configuration from %s", certDir)
	ca, err := readFile(path.Join(certDir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("unable to read CA crt from file %s: %w", path.Join(certDir, caCertFile), err)
	}
	cert, err := readFile(path.Join(certDir, certFile))
	if err != nil {
		return nil, fmt.Errorf("unable to read client crt from file %s: %w", path.Join(certDir, certFile), err)
	}
	key, err := readFile(path.Join(certDir, keyFile))
	if err != nil {
		return nil, fmt.Errorf("unable to read client key from file %s: %w", path.Join(certDir, keyFile), err)
	}

	cPool := x509.NewCertPool()
	if !cPool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("unable to parse CA crt from file %s", path.Join(certDir, caCertFile))
	}

	clientCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt data from file %s: %v", path.Join(certDir, certFile), err)
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}

	return clientTLSConfig, nil
}

func readFile(path string) ([]byte, error) {
	log.Debug().Msgf("Reading file %s", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %s: %w", path, err)
	}

	return data, nil
}
