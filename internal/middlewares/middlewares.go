package middlewares

import (
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
)

// GetMiddlewares returns the list of middlewares to be applied to the request
func GetMiddlewares() []runtime.Middleware {
	// List of middlewares
	// Order of middlewares is important
	// Middlewares are applied in the order they are added in the list
	mws := []runtime.Middleware{
		loggingMiddleware,

		// auth middlewares
		authenticationMiddleware(),
		authorizationMiddleware(),

		// validation middlewares
		validationMiddleware,

		// user create/update interceptor middlewares
		createUserMiddleware,
		updateUserMiddleware,
	}
	return mws

}

// loggingMiddleware logs the request method and path
func loggingMiddleware(next runtime.HandlerFunc) runtime.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		log.Info().Msgf("%s %s", r.Method, r.URL.Path)
		next(w, r, pathParams)
	}
}
