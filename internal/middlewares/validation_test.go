package middlewares

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"

	"github.com/mirantiscontainers/dex-http-server/gen/go/api"
)

func Test_validationMiddlewareCreateUser(t *testing.T) {
	var tests []createUserValidationTest
	tests = append(tests, passwordTests...)
	tests = append(tests, usernameTests...)
	tests = append(tests, emailTests...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock next handler
			mockNext := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
				w.WriteHeader(http.StatusOK)
			}

			// Create a sample request payload
			body, err := marshaler.Marshal(tt.requestBody)
			assert.NoError(t, err)

			// Setup the mock request pattern getter
			requestPatternGetter = mockedRequestPatternGetter("/v1/users")

			// Create a new HTTP request
			req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(body))
			req = req.WithContext(runtime.NewServerMetadataContext(req.Context(), runtime.ServerMetadata{}))

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Call the middleware
			handler := validationMiddleware(mockNext)
			handler(rr, req, map[string]string{})

			fmt.Println(rr.Body.String())
			// Check the response status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func Test_validationMiddlewareUpdateUser(t *testing.T) {
	var tests []updateUserValidationTest
	tests = append(tests, updateUserTests...)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock next handler
			mockNext := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
				w.WriteHeader(http.StatusOK)
			}

			// Create a sample request payload
			body, err := marshaler.Marshal(tt.requestBody)
			assert.NoError(t, err)

			// Setup the mock request pattern getter
			requestPatternGetter = mockedRequestPatternGetter("/users/{email=*}")

			// Create a new HTTP request
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v1/users/%s", tt.requestBody.Email), bytes.NewReader(body))
			req = req.WithContext(runtime.NewServerMetadataContext(req.Context(), runtime.ServerMetadata{}))

			// Create a response recorder
			rr := httptest.NewRecorder()

			pathParams := map[string]string{
				"email": tt.requestBody.Email,
			}
			// Call the middleware
			handler := validationMiddleware(mockNext)
			handler(rr, req, pathParams)

			// Check the response status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

type createUserValidationTest struct {
	name           string
	requestBody    *api.Password
	expectedStatus int
}

var passwordTests = []createUserValidationTest{
	{
		name: "valid create user request",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - min password length",
		requestBody: &api.Password{
			Hash:     []byte(strings.Repeat("a", passwordMinLen)),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - max password length",
		requestBody: &api.Password{
			Hash:     []byte(strings.Repeat("a", passwordMaxLen)),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "invalid create user request - short password",
		requestBody: &api.Password{
			Hash:     []byte("short"),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - short password",
		requestBody: &api.Password{
			Hash:     []byte(strings.Repeat("a", passwordMinLen-1)),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - empty password",
		requestBody: &api.Password{
			Hash:     []byte(""),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - empty spaces password",
		requestBody: &api.Password{
			Hash:     []byte("                 "),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - password containing empty spaces",
		requestBody: &api.Password{
			Hash:     []byte("invalid password"),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - too long password",
		requestBody: &api.Password{
			Hash:     []byte(strings.Repeat("a", passwordMaxLen+1)),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
}

var emailTests = []createUserValidationTest{
	{
		name: "invalid create user request - empty email",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    "",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - empty spaces email",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    "  ",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - short email",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    strings.Repeat("a", minLen-1),
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - long email",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    strings.Repeat("a", maxLen+1),
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - email containing empty spaces",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    "invalid email",
		},
		expectedStatus: http.StatusBadRequest,
	},
}

var usernameTests = []createUserValidationTest{
	{
		name: "valid create user request",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "validusername",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - empty username is allowed",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - empty spaces username is allowed",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "   ",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "invalid create user request - username containing empty spaces",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "invalid username",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - short username",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: "a",
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "invalid create user request - long username",
		requestBody: &api.Password{
			Hash:     []byte("validpassword"),
			Username: strings.Repeat("a", maxLen+1),
			Email:    "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
}

type updateUserValidationTest struct {
	name           string
	requestBody    *api.UpdatePasswordReq
	expectedStatus int
}

var updateUserTests = []updateUserValidationTest{
	{
		name: "valid update user request - updating username and password",
		requestBody: &api.UpdatePasswordReq{
			NewHash:     []byte("validpassword"),
			NewUsername: "validusername",
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid update user request - updating only password",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte("validpassword"),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid update user request - updating only username",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: "validusername",
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},

	{
		name: "valid update user request - min password length",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte(strings.Repeat("a", passwordMinLen)),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - max password length",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte(strings.Repeat("a", passwordMaxLen)),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "invalid update user request - short password",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte("short"),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - short password",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte(strings.Repeat("a", passwordMinLen-1)),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
	{
		name: "invalid create user request - too long password",
		requestBody: &api.UpdatePasswordReq{
			NewHash: []byte(strings.Repeat("a", passwordMaxLen+1)),
			Email:   "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},

	{
		name: "valid update user request - min username length",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: strings.Repeat("a", minLen),
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - max username length",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: strings.Repeat("a", maxLen),
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid update user request - short username",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: "r",
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "valid create user request - username containing empty spaces",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: "invalid username",
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusOK,
	},
	{
		name: "invalid create user request - too long username",
		requestBody: &api.UpdatePasswordReq{
			NewUsername: strings.Repeat("a", maxLen+1),
			Email:       "valid@example.com",
		},
		expectedStatus: http.StatusBadRequest,
	},
}
