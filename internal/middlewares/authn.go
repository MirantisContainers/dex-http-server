package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
)

const (
	dexIssuerURL = "http://authentication-dex:5556/dex"
	dexKeysURL   = "http://authentication-dex:5556/dex/keys"

	dexClientName = "mke-dashboard"
)

// userInfoCtxKey is the key used to store the user information in the request context.

type userInfoKey struct{}

// user contains the user information extracted from the ID token claims.
type user struct {
	email  string
	groups []string
}

var idTokenVerifier *oidc.IDTokenVerifier

// authenticationMiddleware is a middleware that authenticates requests using a bearer token.
// It extracts the token from the Authorization header and verifies it using the ID token verifier.
// If the token is valid, it extracts the user information from the claims and adds it to the request context.
func authenticationMiddleware() runtime.Middleware {

	log.Info().Msg("Initializing ID token verifier")
	idTokenVerifier = oidc.NewVerifier(dexIssuerURL, oidc.NewRemoteKeySet(context.Background(), dexKeysURL), &oidc.Config{ClientID: dexClientName, SkipIssuerCheck: true})

	return func(next runtime.HandlerFunc) runtime.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
			log.Debug().Msg("Authenticating request using bearer token")
			token, err := getBearerToken(r)
			if err != nil {
				log.Error().Err(err).Msg("failed to get authentication token")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			u, err := authenticate(r.Context(), token)
			if err != nil {
				log.Error().Err(err).Msg("failed to authenticate user")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			log.Debug().Msg("Authenticated user: " + u.email)

			// Attach user information to the request context for next middlewares to use
			ctx := context.WithValue(r.Context(), userInfoKey{}, u)

			next(w, r.WithContext(ctx), pathParams)
		}
	}
}

// authenticate verifies a bearer token and pulls user information form the claims.
func authenticate(ctx context.Context, bearerToken string) (*user, error) {
	idToken, err := idTokenVerifier.Verify(ctx, bearerToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify bearer token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}
	if !claims.Verified {
		return nil, fmt.Errorf("email (%q) in returned claims was not verified", claims.Email)
	}
	return &user{claims.Email, claims.Groups}, nil
}

func getBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header not found")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}
