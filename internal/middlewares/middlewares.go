package middlewares

import (
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
)

// Middleware is a function that wraps an http.HandlerFunc
//type Middleware func(http.HandlerFunc) http.HandlerFunc

// GetMiddlewares returns the list of middlewares to be applied to the request
func GetMiddlewares(authDisabled bool) []runtime.Middleware {
	mws := []runtime.Middleware{
		loggingMiddleware,
	}

	// If authentication is not disabled, add the authentication middleware
	if !authDisabled {
		mws = append(mws, authMiddleware()...)
	}

	mws = append(mws, userRequestsMiddleware()...)
	return mws

}

// loggingMiddleware logs the request method and path
func loggingMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		log.Info().Msgf("%s %s", r.Method, r.URL.Path)
		next(w, r, pathParams)
	}
}

// authMiddleware chains the authentication and authorization middleware functions
func authMiddleware() []runtime.Middleware {
	// The list of middleware functions to be applied to the request
	// Note: The order of the middleware functions is important as it
	//       defines the order in which they are applied
	return []runtime.Middleware{
		authenticationMiddleware(),
		authorizationMiddleware(),
	}
}

func userRequestsMiddleware() []runtime.Middleware {
	return []runtime.Middleware{
		createUserMiddleware,
		updateUserMiddleware,
	}
}
