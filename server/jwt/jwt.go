package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

type JwtConfig struct {
	Context        context.Context
	Jwks_url       string
	Logger         *logrus.Logger
	Allowed_scopes []string
	Excluded_paths []string
}

var co *JwtConfig
var jwtKeyFetcher *jwk.AutoRefresh

type JwtError struct {
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
}

type ScpClaim struct {
	Scp []string
}

func InitJWT(conifg *JwtConfig) {

	if co == nil {
		co = conifg
		jwtKeyFetcher = jwk.NewAutoRefresh(co.Context)
		jwtKeyFetcher.Configure(co.Jwks_url,
			jwk.WithMinRefreshInterval(15*time.Minute),
			jwk.WithFetchBackoff(backoff.Constant(backoff.WithInterval(time.Minute))),
		)
	}

}

func errorJson(resp http.ResponseWriter, statuscode int, error *JwtError) {
	resp.WriteHeader(statuscode)
	resp.Header().Add("Content-Type", "application/json; charset=utf-8")
	json_error, _ := json.Marshal(error)
	resp.Write(json_error)
}

func Validate_jwt(w http.ResponseWriter, r *http.Request) error {
	keyset, err := jwtKeyFetcher.Fetch(co.Context, co.Jwks_url)

	token, err := jwt.ParseRequest(r,
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.WithTypedClaim("scope", json.RawMessage{}),
	)
	if err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}

	if err := jwt.Validate(token); err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}

	scopes := getScopes(token)
	haveAllowedScope := haveAllowedScope(scopes, co.Allowed_scopes)
	if !haveAllowedScope {
		errorJson(w, http.StatusUnauthorized, &JwtError{ErrorCode: "InvalidScope", ErrorDescription: "Invalid Scope"})
		return http.ErrAbortHandler
	}
	return nil

}

func JwtHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsExcluded(co.Excluded_paths, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		
		err := Validate_jwt(w, r)
		if err != nil {
			return
		}
		
		next.ServeHTTP(w, r)

	})
}

func haveAllowedScope(scopes []string, allowed_scopes []string) bool {
	if allowed_scopes != nil {
		for _, s := range allowed_scopes {
			isAllowed := Contains(scopes, s)
			if isAllowed {
				return true
			}
		}
	}
	return false
}

func getScopes(token jwt.Token) []string {
	scpInterface := token.PrivateClaims()["scope"]
	scpRaw, _ := scpInterface.(json.RawMessage)
	scopes := []string{}
	json.Unmarshal(scpRaw, &scopes)
	return scopes
}

