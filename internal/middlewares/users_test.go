package middlewares

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/mirantiscontainers/dex-http-server/gen/go/api"
)

var mockedRequestPatternGetter = func(patternToReturn string) func(r *http.Request) (string, error) {
	return func(r *http.Request) (string, error) {
		return patternToReturn, nil
	}
}

func Test_createUserMiddleware(t *testing.T) {
	// Mock mockNext handler

	requestPatternGetter = mockedRequestPatternGetter("/v1/users")

	plainTextPassword := "mysecretpassword"
	mockNext := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		// Decode the modified request body
		var req api.CreatePasswordReq
		err := marshaler.NewDecoder(r.Body).Decode(&req.Password)
		assert.NoError(t, err)

		// Check if the password was correctly encrypted
		err = bcrypt.CompareHashAndPassword(req.Password.Hash, []byte(plainTextPassword))
		assert.NoError(t, err, "password was not encrypted")

		// Check if the UUID is generated
		_, err = uuid.Parse(req.Password.UserId)
		assert.NoError(t, err, "userId is not a valid UUID")
	}

	// Create a sample request payload
	body := fmt.Sprintf(`
	{
		"hash": "%s",
		"userId": "someuuid"
	}
	`, base64.StdEncoding.EncodeToString([]byte(plainTextPassword)))

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader([]byte(body)))

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the middleware
	handler := createUserMiddleware(mockNext)
	handler(rr, req, nil)

	// Check the response status code
	assert.Equal(t, http.StatusOK, rr.Code)
}

func Test_updateUserMiddleware(t *testing.T) {

	requestPatternGetter = mockedRequestPatternGetter("/users/{email=*}")

	newPlainTextPassword := "mysecretpassword"
	newUsername := "mysecretpassword"
	mockNext := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		// Decode the modified request body
		var req api.UpdatePasswordReq
		err := marshaler.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		// Check if the new password is encrypted
		err = bcrypt.CompareHashAndPassword(req.NewHash, []byte(newPlainTextPassword))
		assert.NoError(t, err)

		// Check if the new username is correct
		assert.Equal(t, newUsername, req.NewUsername)
	}

	reqBodyStr := fmt.Sprintf(`
	{
		"newHash": "%s",
		"newUsername": "%s"
	}
`, base64.StdEncoding.EncodeToString([]byte(newPlainTextPassword)), newUsername)

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodPut, "/users/myuser1", bytes.NewReader([]byte(reqBodyStr)))
	req = req.WithContext(runtime.NewServerMetadataContext(req.Context(), runtime.ServerMetadata{}))

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the middleware
	handler := updateUserMiddleware(mockNext)
	handler(rr, req, map[string]string{})

	// Check the response status code
	assert.Equal(t, http.StatusOK, rr.Code)
}

func Test_isCreateUserRequest(t *testing.T) {

	tests := []struct {
		method  string
		pattern string
		want    bool
	}{
		{method: http.MethodPost, pattern: "/users", want: true},
		{method: http.MethodPost, pattern: "/v1/users", want: true},
		{method: http.MethodPost, pattern: "/api/dex/v1/users", want: true},

		{method: http.MethodGet, pattern: "/users", want: false},
		{method: http.MethodPut, pattern: "/users", want: false},

		{method: http.MethodPost, pattern: "/users/verify", want: false},
	}
	for _, test := range tests {
		if got := isCreateUserRequest(test.method, test.pattern); got != test.want {
			t.Errorf("isCreateUserRequest() with %s %s = %v, want %v", test.method, test.pattern, got, test.want)
		}
	}
}

func Test_isUpdateUserRequest(t *testing.T) {

	tests := []struct {
		method  string
		pattern string
		want    bool
	}{
		{method: http.MethodPut, pattern: "/users/{email=*}", want: true},
		{method: http.MethodPut, pattern: "/v1/users/{email=*}", want: true},
		{method: http.MethodPut, pattern: "/api/dex/v1/users/{email=*}", want: true},

		{method: http.MethodGet, pattern: "/users/{email=*}", want: false},
		{method: http.MethodPost, pattern: "/users/{email=*}", want: false},

		{method: http.MethodPut, pattern: "/users/verify/{email=*}", want: false},
	}
	for _, test := range tests {
		if got := isUpdateUserRequest(test.method, test.pattern); got != test.want {
			t.Errorf("getUserRequest() = %v, want %v", got, test.want)
		}
	}
}

func Test_encryptPassword(t *testing.T) {
	password := []byte("mysecretpassword")
	encrypted, err := encryptPasswordHash(password)
	if err != nil {
		t.Fatalf("encryptPasswordHash() error = %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(encrypted), password); err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword() error = %v", err)
	}
}
