package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/config"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var co *config.Jwt
var jwtKeyFetcher *jwk.AutoRefresh

// TODO: Remove CreateJWT if unused
func CreateJWT(key []byte) (string, error) {
	claims := jwt.New()
	// claims.Set(jwt.IssuerKey, "issuer")
	// claims.Set(jwt.AudienceKey, "audience_key")
	// claims.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))
	// claims.Set(jwt.NotBeforeKey, time.Now().Add(-1*time.Minute))
	// claims.Set(jwt.IssuedAtKey, time.Now())
	// claims.Set(jwt.JwtIDKey, "token_id")
	claims.Set("scope", []string{"scope1", "scope2", "scope3"})

	token, err := jwt.Sign(claims, jwa.HS256, key)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

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
	// keyset, err := jwtKeyFetcher.Fetch(co.Context, co.Jwks_url)

	token, err := jwt.ParseRequest(r,
		// jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.WithTypedClaim("scope", json.RawMessage{}),
		jwt.WithTypedClaim("scp", json.RawMessage{}),
	)
	if err != nil {
		// TODO: Uncomment co.Logger.Info
		// co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}

	if err := jwt.Validate(token); err != nil {
		co.Logger.Info("Error jwt:", err)
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "JsonWebTokenError", ErrorDescription: err.Error()})
		return http.ErrAbortHandler
	}
	scopes := getScopes(token)
	haveAllowedScope := haveAllowedScope(scopes, co.Allowed_scopes)
	if !haveAllowedScope {
		errorJson(w, http.StatusUnauthorized, &config.JwtError{ErrorCode: "InvalidScope", ErrorDescription: "Invalid Scope"})
		return http.ErrAbortHandler
	}
	return nil

}

func JWTHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("------r.host", r.Host)
		test := config.Config.Domains[r.Host]
		fmt.Print("------config.Config.Domains[r.Host]", test.Jwt.Allowed_scopes)
		if IsIncluded(co.Included_paths, r.URL.Path) {
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