package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/config"
	"github.com/fabiocicerchia/go-proxy-cache/server/handler"
	"github.com/fabiocicerchia/go-proxy-cache/utils/slice"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
)

var co *config.Jwt
var jwtKeyFetcher *jwk.AutoRefresh

func InitJWT(jwtConfig *config.Jwt) {
	co = jwtConfig
	refreshIntervalDuration := time.Duration(co.JwksRefreshInterval) * time.Minute
	jwtKeyFetcher = jwk.NewAutoRefresh(context.Background())
	jwtKeyFetcher.Configure(co.JwksUrl,
		jwk.WithMinRefreshInterval(refreshIntervalDuration),
		jwk.WithFetchBackoff(backoff.Constant(backoff.WithInterval(time.Minute))),
	)
}

func InitJWTWithDomainConf(domainJWTConfig config.Jwt) {
	jwksUrl := getJWKSUrl(domainJWTConfig)
	allowedScopes := getJWTAllowedScopes(domainJWTConfig)
	includedPaths := getJWTIncludedPaths(domainJWTConfig)
	jwksRefreshInterval := getJWTJwksRefreshInterval(domainJWTConfig)
	InitJWT(&config.Jwt{
		IncludedPaths:       includedPaths,
		AllowedScopes:       allowedScopes,
		JwksUrl:             jwksUrl,
		JwksRefreshInterval: jwksRefreshInterval,
		Context:             context.Background(),
		Logger:              log.New(),
	})
}

func getJWKSUrl(domainJWTConfig config.Jwt) string {
	if domainJWTConfig.JwksUrl != "" {
		return domainJWTConfig.JwksUrl
	}

	return config.Config.Jwt.JwksUrl
}

func getJWTAllowedScopes(domainJWTConfig config.Jwt) []string {
	if domainJWTConfig.AllowedScopes != nil {
		return domainJWTConfig.AllowedScopes
	}

	return config.Config.Jwt.AllowedScopes
}

func getJWTIncludedPaths(domainJWTConfig config.Jwt) []string {
	if domainJWTConfig.IncludedPaths != nil {
		return domainJWTConfig.IncludedPaths
	}
	return config.Config.Jwt.IncludedPaths
}

func getJWTJwksRefreshInterval(domainJWTConfig config.Jwt) int {
	if domainJWTConfig.JwksRefreshInterval != 0 {
		return domainJWTConfig.JwksRefreshInterval
	}

	return config.Config.Jwt.JwksRefreshInterval
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
	haveAllowedScope := haveAllowedScope(scopes, co.AllowedScopes)
	if !haveAllowedScope {
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "InvalidScope", ErrorDescription: "Invalid Scope"})
		return http.ErrAbortHandler
	}

	return nil
}

func fetchKeySet(w http.ResponseWriter) (jwk.Set, error) {
	keySet, err := jwtKeyFetcher.Fetch(co.Context, co.JwksUrl)
	if err != nil {
		return keySet, logJWTErrorAndAbort(w, err)
	}

	return keySet, nil
}

func JWTHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := handler.NewRequestCall(w, r)
		domainConfig, isDomain := config.DomainConf(r.Host, rc.GetScheme())
		var includedPaths []string
		if isDomain && domainConfig.Jwt.IncludedPaths != nil {
			includedPaths = domainConfig.Jwt.IncludedPaths
		} else {
			includedPaths = config.Config.Jwt.IncludedPaths
		}
		if IsIncluded(includedPaths, r.URL.Path) {
			keySet, err := fetchKeySet(w)
			if err != nil {
				return
			}
			err = ValidateJWT(w, r, keySet)
			if err != nil {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func haveAllowedScope(scopes []string, allowedScopes []string) bool {
	if allowedScopes != nil {
		for _, s := range allowedScopes {
			isAllowed := slice.ContainsString(scopes, s)
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
