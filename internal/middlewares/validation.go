package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"

	"github.com/mirantiscontainers/dex-http-server/gen/go/api"
)

const (
	passwordMinLen = 8
	passwordMaxLen = 64

	// minLen is the minimum length of the username, email
	minLen = 3

	// maxLen is the maximum length of the username, email
	maxLen = 100
)

// validationMiddleware validates the request body for create and update user requests
// It checks the length of the username, email and password
func validationMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		if getRequestName(r) == requestCreateUser || getRequestName(r) == requestUpdateUser {
			var reqPassword api.Password
			if err := marshaler.NewDecoder(r.Body).Decode(&reqPassword); err != nil {
				log.Err(err).Msg("failed to decode request body")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := validateUserRequest(&reqPassword); err != nil {
				log.Err(err).Msg("failed to validate user request")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		next(w, r, pathParams)
	}
}

func validateUserRequest(userPassword *api.Password) error {
	password := strings.TrimSpace(string(userPassword.Hash))
	username := strings.TrimSpace(userPassword.Username)
	email := strings.TrimSpace(userPassword.Email)

	if err := validateLength(password, passwordMinLen, passwordMaxLen); err != nil {
		return fmt.Errorf("failed to validate password, %v", err.Error())
	}

	if err := validateLength(username, minLen, maxLen); err != nil {
		return fmt.Errorf("failed to validate username, %v", err.Error())
	}

	if err := validateLength(email, minLen, maxLen); err != nil {
		return fmt.Errorf("failed to validate email, %v", err.Error())
	}

	return nil

}

func validateLength(s string, min, max int) error {
	if len(s) < min {
		return fmt.Errorf("must be at least %v characters", min)
	}

	if len(s) > max {
		return fmt.Errorf("must be at most %v characters", max)
	}
	return nil
}
