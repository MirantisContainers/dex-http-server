package middlewares

import (
	"bytes"
	"fmt"
	"io"
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
		if getRequestName(r) == requestCreateUser {
			validateCreateUserRequest(next, w, r, pathParams)
		} else if getRequestName(r) == requestUpdateUser {
			validateUpdateUserRequest(next, w, r, pathParams)
		} else {
			next(w, r, pathParams)
		}
	}
}

func validateCreateUserRequest(next runtime.HandlerFunc, w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	var req api.CreatePasswordReq
	if err := marshaler.NewDecoder(r.Body).Decode(&req.Password); err != nil {
		log.Err(err).Msg("failed to decode request body while validating create user request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	if err := validateUserRequest(req.Password); err != nil {
		log.Err(err).Msg("failed to validate user request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// add back the request body
	newCreateUserReq, err := marshaler.Marshal(&req.Password)
	if err != nil {
		log.Err(err).Msg("failed to marshal request after validating create user request")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(newCreateUserReq))
	next(w, r, pathParams)
}

func validateUpdateUserRequest(next runtime.HandlerFunc, w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	var req api.UpdatePasswordReq
	if err := marshaler.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Err(err).Msg("failed to decode request body while validating update user request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	// email field is extracted from the path params in this middleware
	// The gRPC gateway will populate the req.Email field with the email from the path params
	// but that happens after this middleware is called
	email := strings.TrimSpace(pathParams["email"])
	if len(email) == 0 {
		log.Err(fmt.Errorf("email is required")).Msg("failed to validate email")
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	newUsername := strings.TrimSpace(req.NewUsername)
	newHash := strings.TrimSpace(string(req.NewHash))

	// only username when it is provided as it is optional
	if len(newUsername) > 0 {
		if err := validateUsername(newUsername); err != nil {
			log.Err(err).Msg("failed to validate username")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// only validate newhash when it is provided as it is optional
	if len(newHash) > 0 {
		if err := validatePassword(newHash); err != nil {
			log.Err(err).Msg("failed to validate password")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// add back the request body
	newUpdatePasswordReq, err := marshaler.Marshal(&req)
	if err != nil {
		log.Err(err).Msg("failed to marshal request after encrypting password")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(newUpdatePasswordReq))
	next(w, r, pathParams)
}

func validateUserRequest(userPassword *api.Password) error {
	password := strings.TrimSpace(string(userPassword.Hash))
	username := strings.TrimSpace(userPassword.Username)
	email := strings.TrimSpace(userPassword.Email)

	if err := validateEmail(email); err != nil {
		return err
	}

	if err := validatePassword(password); err != nil {
		return err
	}

	// username is optional field
	if len(username) > 0 {
		if err := validateUsername(username); err != nil {
			return err
		}
	}

	return nil
}

func validateEmail(email string) error {
	if err := validateLength(email, minLen, maxLen); err != nil {
		return fmt.Errorf("failed to validate email, %v", err.Error())
	}
	return nil
}

func validatePassword(password string) error {
	if err := validateLength(password, passwordMinLen, passwordMaxLen); err != nil {
		return fmt.Errorf("failed to validate password, %v", err.Error())
	}

	return nil
}

func validateUsername(username string) error {
	if err := validateLength(username, minLen, maxLen); err != nil {
		return fmt.Errorf("failed to validate username, %v", err.Error())
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
