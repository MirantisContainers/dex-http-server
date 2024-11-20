package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
)

type requestName string

var (
	requestCreateUser requestName = "CreateUser"
	requestUpdateUser requestName = "UpdateUser"
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

// getRequestName returns the name of the request based on the method and path pattern
// For example:
//
//	if the request is a POST to /users, the name will be CreateUser
//	if the request is a PUT to /users/{email=*}, the name will be UpdateUser
func getRequestName(r *http.Request) requestName {
	pattern, err := requestPatternGetter(r)
	if err != nil {
		log.Error().Err(err).Msg("failed to get request name")
		return ""
	}

	if isCreateUserRequest(r.Method, pattern) {
		return requestCreateUser
	}

	if isUpdateUserRequest(r.Method, pattern) {
		return requestUpdateUser
	}

	return ""
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
