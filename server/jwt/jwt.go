package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/config"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
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

func InitJWTWithDomainConf(domainConfig config.Configuration) {
	var jwtUrl string
	var allowedScopes, includedPaths []string
	if domainConfig.Jwt.Jwks_url != "" {
		jwtUrl = domainConfig.Jwt.Jwks_url
	} else {
		jwtUrl = config.Config.Jwt.Jwks_url
	}
	if domainConfig.Jwt.Allowed_scopes != nil {
		allowedScopes = domainConfig.Jwt.Allowed_scopes
	} else {
		allowedScopes = config.Config.Jwt.Allowed_scopes
	}
	if domainConfig.Jwt.Included_paths != nil {
		includedPaths = domainConfig.Jwt.Included_paths
	} else {
		includedPaths = config.Config.Jwt.Included_paths
	}
	InitJWT(&config.Jwt{
		Included_paths: includedPaths,
		Allowed_scopes: allowedScopes,
		Jwks_url:       jwtUrl,
		Context:        context.Background(),
		Logger:         log.New(),
	})
}

func errorJson(resp http.ResponseWriter, statuscode int, error *config.JwtError) {
	resp.WriteHeader(statuscode)
	resp.Header().Add("Content-Type", "application/json; charset=utf-8")
	json_error, _ := json.Marshal(error)
	resp.Write(json_error)
}

func logJWTErrorAndAbort(w http.ResponseWriter, err error) error {
	co.Logger.Info("Error jwt:", err)
	errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})

	return http.ErrAbortHandler
}

func ValidateJWT(w http.ResponseWriter, r *http.Request, keySet jwk.Set) error {
	token, err := jwt.ParseRequest(r,
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithTypedClaim("scope", json.RawMessage{}),
		jwt.WithTypedClaim("scp", json.RawMessage{}),
	)
	if err != nil {
		return logJWTErrorAndAbort(w, err)
	}
	if err := jwt.Validate(token); err != nil {
		return logJWTErrorAndAbort(w, err)
	}
	scopes := getScopes(token)
	haveAllowedScope := haveAllowedScope(scopes, co.Allowed_scopes)
	if !haveAllowedScope {
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "InvalidScope", ErrorDescription: "Invalid Scope"})
		return http.ErrAbortHandler
	}

	return nil
}

func fetchKeySet(w http.ResponseWriter) (jwk.Set, error) {
	keySet, err := jwtKeyFetcher.Fetch(co.Context, co.Jwks_url)
	if err != nil {
		return keySet, logJWTErrorAndAbort(w, err)
	}

	return keySet, nil
}

func JWTHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domainConfig, isDomain := config.DomainConf(r.URL.Host, r.URL.Scheme)
		var includedPaths []string
		if isDomain && domainConfig.Jwt.Included_paths != nil {
			includedPaths = domainConfig.Jwt.Included_paths
		} else {
			includedPaths = config.Config.Jwt.Included_paths
		}
		if IsIncluded(includedPaths, r.URL.Path) {
			co = nil
			InitJWTWithDomainConf(domainConfig)
			keySet, err := fetchKeySet(w)
			if err != nil {
				return
			}
			err = ValidateJWT(w, r, keySet)
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
