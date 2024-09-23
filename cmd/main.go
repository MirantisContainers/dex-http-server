package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/grpclog"

	"github.com/mirantiscontainers/dex-http-server/gen/go/api"
	"github.com/mirantiscontainers/dex-http-server/internal/tls"
)

var (
	// command-line options:
	// gRPC server endpoint
	grpcServerEndpoint = flag.String("grpc-server", "dex:5557", "gRPC server endpoint")

	// HTTP server port
	port = flag.String("http-port", "8080", "HTTP server port")

	// HTTP server port
	certsPath = flag.String("grpc-certs-path", "", "Path to the directory containing the grpc certs")

	version, commit, date = "", "", "" // These are always injected at build time
)

func run() error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var err error
	var creds credentials.TransportCredentials

	// Load the cert from the file, if provided
	if *certsPath != "" {
		log.Info().Msgf("Using cert for grpc connect from %s", *certsPath)
		creds, err = getDexGrpcCredentials(*certsPath)
		if err != nil {
			return fmt.Errorf("failed to get grpc credentials: %w", err)
		}
	} else {
		log.Info().Msg("No cert provided, using insecure connection")
		creds = insecure.NewCredentials()
	}

	// Register gRPC server endpoint
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if err = api.RegisterDexHandlerFromEndpoint(ctx, mux, *grpcServerEndpoint, opts); err != nil {
		return err
	}
	log.Info().Msgf("Registered gRPC server endpoint: %s", *grpcServerEndpoint)

	// Start HTTP server (and proxy calls to gRPC server endpoint)
	log.Info().Msgf("Running HTTP server on %s", *port)
	return http.ListenAndServe(":"+*port, mux)
}

func getDexGrpcCredentials(tlsDir string) (credentials.TransportCredentials, error) {
	tlsConfig, err := tls.LoadTLSConfig(tlsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}
	return credentials.NewTLS(tlsConfig), nil

}

func main() {
	flag.Parse()

	log.Info().Msg("Starting dex-http-server")
	log.Info().Msgf("Version: %s", version)
	log.Info().Msgf("Commit: %s", commit)
	log.Info().Msgf("Date: %s", date)

	if err := run(); err != nil {
		grpclog.Fatal(err)
	}
}
