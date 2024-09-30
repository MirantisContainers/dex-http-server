package middlewares

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/mirantiscontainers/dex-http-server/gen/go/api"
)

var (
	// marshaler is a JSON marshaler that uses proto field names
	// This is required to properly marshal the request body as the
	// field names are generated from the proto file
	marshaler = runtime.HTTPBodyMarshaler{
		Marshaler: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames: true,
			},
		},
	}
)

// requestPatternGetter is a function that extracts the path pattern from the request
// The function is defined as a variable so that it can be mocked in tests
var requestPatternGetter = func(r *http.Request) (string, error) {
	pattern, exists := runtime.HTTPPattern(r.Context())
	if !exists {
		return "", fmt.Errorf("failed to get path pattern from request")
	}

	return pattern.String(), nil
}

// createUserMiddleware is a middleware that intercepts and modifies the request body to:
// - encrypt the password using bcrypt
// - generate a UUID for the user
// This middleware is applied to create user requests only
func createUserMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		pattern, err := requestPatternGetter(r)
		if err != nil {
			log.Err(err).Msg("failed to get http request pattern")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if isCreateUserRequest(r.Method, pattern) {
			log.Debug().Msg("create user request, will modify request body to encrypt password and generate UUID")

			// decode request body
			// note: we are decoding req.Password (instead of req) because the request body is modified
			//       to contain only the Password object, and not the entire CreatePasswordReq object
			var req api.CreatePasswordReq
			if err = marshaler.NewDecoder(r.Body).Decode(&req.Password); err != nil {
				log.Err(err).Msg("failed to decode request body")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// replace password with bcrypt hash
			plaintext := req.Password.Hash
			encrypted, err := encryptPasswordHash(plaintext)
			if err != nil {
				log.Err(err).Msg("failed to encrypt password")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.Password.Hash = []byte(encrypted)

			// Also replace user id with generate UUID
			// Dex server accepts duplicate user ids, so we need to generate a unique id
			// for each user. Not sure how is this field used in dex
			req.Password.UserId = generateUUID()

			// update request body
			// note: similarly, we are encoding req.Password (instead of req) because the request body is modified
			//       to contain only the Password object, and not the entire CreatePasswordReq object
			newCreatePasswordReq, err := marshaler.Marshal(&req.Password)
			if err != nil {
				log.Err(err).Msg("failed to marshal request after encrypting password")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(newCreatePasswordReq))
		}
		next(w, r, pathParams)
	}
}

func updateUserMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		pattern, err := requestPatternGetter(r)
		if err != nil {
			log.Err(err).Msg("failed to get http request pattern")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if isUpdateUserRequest(r.Method, pattern) {
			log.Debug().Msg("update password request, will modify request body to encrypt password")

			// decode request body
			var req api.UpdatePasswordReq
			if err = marshaler.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// replace password with base64 of bcrypt hash
			plaintext := req.NewHash
			encryptedHash, err := encryptPasswordHash(plaintext)
			if err != nil {
				log.Err(err).Msg("failed to encrypt password")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.NewHash = []byte(encryptedHash)

			// update request body
			newUpdatePasswordReq, err := marshaler.Marshal(&req)
			if err != nil {
				log.Err(err).Msg("failed to marshal request after encrypting password")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(newUpdatePasswordReq))
		}

		next(w, r, pathParams)
	}
}

// encryptPasswordHash encrypts the password using bcrypt and return base64 encoded hash
func encryptPasswordHash(password []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func generateUUID() string {
	return uuid.New().String()
}

func isCreateUserRequest(method, pattern string) bool {
	result := method == http.MethodPost && strings.HasSuffix(pattern, "/users")
	log.Debug().Msgf("checking if request is create user request with method=%s, pattern=%s, result=%v", method, pattern, result)
	return result
}

func isUpdateUserRequest(method, pattern string) bool {
	result := method == http.MethodPut && strings.HasSuffix(pattern, "/users/{email=*}")
	log.Debug().Msgf("checking if request is update user request with method=%s, pattern=%s, result=%v", method, pattern, result)
	return result
}
