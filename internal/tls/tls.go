package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path"
)

const (
	caCertFile = "ca.crt"
	certFile   = "tls.crt"
	keyFile    = "tls.key"
)

// LoadTLSConfig loads the TLS configuration from the provided directory
func LoadTLSConfig(certDir string) (*tls.Config, error) {
	ca, err := readFile(path.Join(certDir, caCertFile))
	cert, err := readFile(path.Join(certDir, certFile))
	key, err := readFile(path.Join(certDir, keyFile))

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
