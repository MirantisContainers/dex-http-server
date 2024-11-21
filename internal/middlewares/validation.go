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

// *********************************************************************************************
// NOTE: The fields from api.Password (Dex) are mapped to different fields in the UI
//       api.Password.Email -> username field in the UI
//       api.Password.Username -> name field in the UI
// 		 api.Password.Hash -> password field in the UI
//
// The validation functions are named as such to reflect the fields in the UI
// The response from the validation functions are also formatted to reflect the fields in the UI
// **********************************************************************************************

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

	// username field is extracted from the path params 'email' in this middleware
	// The gRPC gateway will populate the req.Email field with the username from the path params
	// but that happens after this middleware is called
	username := strings.TrimSpace(pathParams["email"])
	if len(username) == 0 {
		log.Err(fmt.Errorf("username is required")).Msg("invalid username")
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	newName := strings.TrimSpace(req.NewUsername)
	newPassword := string(req.NewHash)

	// only username when it is provided as it is optional
	if len(newName) > 0 {
		if err := validateName(newName); err != nil {
			log.Err(err).Msg("invalid name")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// only validate newPassword when it is provided as it is optional
	if len(newPassword) > 0 {
		if err := validatePassword(newPassword); err != nil {
			log.Err(err).Msg("invalid password")
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
	username := strings.TrimSpace(userPassword.Email)
	password := strings.TrimSpace(string(userPassword.Hash))
	name := strings.TrimSpace(userPassword.Username)

	if err := validateUsername(username); err != nil {
		return err
	}

	if err := validatePassword(password); err != nil {
		return err
	}

	// name is optional field
	if len(name) > 0 {
		if err := validateName(name); err != nil {
			return err
		}
	}

	return nil
}

// note: email is mapped to 'username' in the UI. Therefore, we validate the email as the username
func validateUsername(username string) error {
	if strings.Contains(username, " ") {
		return fmt.Errorf("username cannot contain white spaces")
	}

	if err := validateLength(username, minLen, maxLen); err != nil {
		return fmt.Errorf("invalid username, %v", err.Error())
	}
	return nil
}

func validatePassword(password string) error {
	// allow no white spaces in the password
	if strings.Contains(password, " ") {
		return fmt.Errorf("password cannot contain white spaces")
	}

	if err := validateLength(password, passwordMinLen, passwordMaxLen); err != nil {
		return fmt.Errorf("invalid password, %v", err.Error())
	}

	return nil
}

func validateName(name string) error {
	if err := validateLength(name, 0, maxLen); err != nil {
		return fmt.Errorf("invalid name, %v", err.Error())
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
