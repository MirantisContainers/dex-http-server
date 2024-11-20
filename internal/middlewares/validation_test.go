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
	tests := getTests()

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

			// Check the response status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func Test_validationMiddlewareUpdateUser(t *testing.T) {
	tests := getTests()

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

			// Call the middleware
			handler := validationMiddleware(mockNext)
			handler(rr, req, map[string]string{})

			// Check the response status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func getTests() []struct {
	name           string
	requestBody    *api.Password
	expectedStatus int
} {
	tests := []struct {
		name           string
		requestBody    *api.Password
		expectedStatus int
	}{
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
			name: "invalid create user request - too long password",
			requestBody: &api.Password{
				Hash:     []byte(strings.Repeat("a", passwordMaxLen+1)),
				Username: "validusername",
				Email:    "valid@example.com",
			},
			expectedStatus: http.StatusBadRequest,
		},

		{
			name: "invalid create user request - short username",
			requestBody: &api.Password{
				Hash:     []byte("validpassword"),
				Username: strings.Repeat("a", minLen-1),
				Email:    "valid@example.com",
			},
			expectedStatus: http.StatusBadRequest,
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
	}
	return tests
}
