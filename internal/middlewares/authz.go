package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"k8s.io/client-go/kubernetes"

	"github.com/mirantiscontainers/dex-http-server/internal/roles"
)

var (
	kubeClient kubernetes.Interface

	// List of cluster roles that are allowed to access the dashboard
	// @todo (ranyodh): This should be configurable from command line args
	clusterRoles = []string{
		"cluster-admin",
	}
)

// authorizationMiddleware is a middleware that authorizes requests based on the user information in the context.
func authorizationMiddleware(h http.HandlerFunc) http.HandlerFunc {
	log.Info().Msg("Initialized kubernetes client")
	log.Debug().Msg("Allowed cluster roles: " + strings.Join(clusterRoles, ", "))

	var err error
	kubeClient, err = roles.NewClientSet()
	if err != nil {
		log.Error().Err(err).Msg("failed to initialize kubernetes client")
		panic("failed to initialize kubernetes client")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msg("Authorizing request")

		// get user info from the context
		u := r.Context().Value(userInfoCtxKey)
		if u == nil {
			log.Error().Err(fmt.Errorf("failed to get user info from context"))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		userInfo, ok := u.(*user)
		if !ok {
			log.Error().Err(fmt.Errorf("failed to parse user info from context"))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// only allow if the user has the required cluster roles
		allowed, err := authorize(userInfo)
		if err != nil {
			log.Error().Err(err).Msg("failed to authorize user")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	}
}

// authorize checks if the user has the required cluster roles to access the dashboard.
func authorize(u *user) (bool, error) {
	if u == nil {
		return false, fmt.Errorf("user info is nil")
	}

	log.Debug().Msg("Authorizing request for user: " + u.email)
	cr, err := roles.GetClusterRoles(context.Background(), kubeClient, u.email)
	if err != nil {
		return false, fmt.Errorf("failed to get cluster roles for the user: %v", err)
	}

	log.Debug().Msg("Cluster roles: " + strings.Join(cr, ", "))

	if containsAny(clusterRoles, cr) {
		return true, nil
	}

	return false, nil
}

// containsAny returns true if any of the elements in arr2 are in arr1
func containsAny(arr1, arr2 []string) bool {
	for _, v := range arr2 {
		if slices.Contains(arr1, v) {
			return true
		}
	}
	return false
}
