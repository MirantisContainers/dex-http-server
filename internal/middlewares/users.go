package middlewares

import (
	"bytes"
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

// createUserMiddleware is a middleware that intercepts and modifies the request body to:
// - encrypt the password using bcrypt
// - generate a UUID for the user
// This middleware is applied to create user requests only
func createUserMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		if getRequestName(r) == requestCreateUser {
			log.Debug().Msg("create user request, will modify request body to encrypt password and generate UUID")

			// decode request body
			// note: we are decoding req.Password (instead of req) because the request body is modified
			//       to contain only the Password object, and not the entire CreatePasswordReq object
			var req api.CreatePasswordReq
			if err := marshaler.NewDecoder(r.Body).Decode(&req.Password); err != nil {
				log.Err(err).Msg("failed to decode request body while creating user")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()

			// replace password with bcrypt hash
			plaintext := req.Password.Hash
			encrypted, err := encryptPasswordHash(plaintext)
			if err != nil {
				log.Err(err).Msg("failed to encrypt password")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.Password.Hash = []byte(encrypted)

			// trim spaces from email and username
			req.Password.Email = strings.TrimSpace(req.Password.Email)
			req.Password.Username = strings.TrimSpace(req.Password.Username)

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
		if getRequestName(r) == requestUpdateUser {
			log.Debug().Msg("update user request, will modify request body to encrypt password")

			// decode request body
			var req api.UpdatePasswordReq
			if err := marshaler.NewDecoder(r.Body).Decode(&req); err != nil {
				log.Err(err).Msg("failed to decode request body while updating user")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()

			if len(req.NewHash) > 0 {
				log.Debug().Msg("update password request, will modify request body to encrypt password")

				// replace password with base64 of bcrypt hash
				plaintext := req.NewHash
				encryptedHash, err := encryptPasswordHash(plaintext)
				if err != nil {
					log.Err(err).Msg("failed to encrypt password")
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				req.NewHash = []byte(encryptedHash)
			}

			req.NewUsername = strings.TrimSpace(req.NewUsername)

			// add back the request body
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
