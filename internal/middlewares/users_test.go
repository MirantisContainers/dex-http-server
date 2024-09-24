package middlewares

import (
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

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
	encrypted, err := encryptPassword(password)
	if err != nil {
		t.Fatalf("encryptPassword() error = %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(encrypted), password); err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword() error = %v", err)
	}
}
