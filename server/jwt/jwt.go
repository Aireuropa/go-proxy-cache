package jwt

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/config"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var co *config.Jwt
var jwtKeyFetcher *jwk.AutoRefresh

func InitJWT(conifg *config.Jwt) {

	if co == nil {
		co = conifg
		jwtKeyFetcher = jwk.NewAutoRefresh(co.Context)
		jwtKeyFetcher.Configure(co.Jwks_url,
			jwk.WithMinRefreshInterval(15*time.Minute),
			jwk.WithFetchBackoff(backoff.Constant(backoff.WithInterval(time.Minute))),
		)
	}
}

func errorJson(resp http.ResponseWriter, statuscode int, error *config.JwtError) {
	resp.WriteHeader(statuscode)
	resp.Header().Add("Content-Type", "application/json; charset=utf-8")
	json_error, _ := json.Marshal(error)
	resp.Write(json_error)
}

func ValidateJWT(w http.ResponseWriter, r *http.Request) error {
	keyset, err := jwtKeyFetcher.Fetch(co.Context, co.Jwks_url)
	if err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}
	token, err := jwt.ParseRequest(r,
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.WithTypedClaim("scope", json.RawMessage{}),
		jwt.WithTypedClaim("scp", json.RawMessage{}),
	)
	if err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}

	if err := jwt.Validate(token); err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}
	scopes := getScopes(token)
	domainConfig, isDomain := config.DomainConf(r.URL.Host, r.URL.Scheme)
	var allowedScopes []string
	if isDomain && domainConfig.Jwt.Allowed_scopes != nil {
		allowedScopes = domainConfig.Jwt.Allowed_scopes
	} else {
		allowedScopes = co.Allowed_scopes
	}
	haveAllowedScope := haveAllowedScope(scopes, allowedScopes)
	if !haveAllowedScope {
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "InvalidScope", ErrorDescription: "Invalid Scope"})
		return http.ErrAbortHandler
	}
	return nil

}

func JWTHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domainConfig, isDomain := config.DomainConf(r.URL.Host, r.URL.Scheme)
		var includedPaths []string
		if isDomain && domainConfig.Jwt.Included_paths != nil {
			includedPaths = domainConfig.Jwt.Included_paths
		} else {
			includedPaths = co.Included_paths
		}
		if IsIncluded(includedPaths, r.URL.Path) {
			err := ValidateJWT(w, r)
			if err != nil {
				return
			}

			next.ServeHTTP(w, r)
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
	_, isScp := token.Get("scp")
	if isScp {
		scpInterface := token.PrivateClaims()["scp"]
		return extractScopes(scpInterface)
	}
	scopeInterface := token.PrivateClaims()["scope"]
	return extractScopes(scopeInterface)
}

func extractScopes(scopesInterface interface{}) []string {
	scpRaw, _ := scopesInterface.(json.RawMessage)
	scopes := []string{}
	json.Unmarshal(scpRaw, &scopes)
	return scopes
}
