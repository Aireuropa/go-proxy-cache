package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/cache/engine"
	"github.com/fabiocicerchia/go-proxy-cache/config"
	logger "github.com/fabiocicerchia/go-proxy-cache/logger"
	"github.com/fabiocicerchia/go-proxy-cache/server/handler"
	"github.com/fabiocicerchia/go-proxy-cache/telemetry/tracing"
	"github.com/fabiocicerchia/go-proxy-cache/utils"
	circuit_breaker "github.com/fabiocicerchia/go-proxy-cache/utils/circuit-breaker"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func getCommonConfig() config.Configuration {
	// TODO: Implement tags and uncomment initLogs()
	//initLogs()

	return config.Configuration{
		Cache: config.Cache{
			Hosts: []string{utils.GetEnv("REDIS_HOSTS", "localhost:6379")},
			DB:    0,
		},
		CircuitBreaker: circuit_breaker.CircuitBreaker{
			Threshold:   2,   // after 2nd request, if meet FailureRate goes open.
			FailureRate: 0.5, // 1 out of 2 fails, or more
			Interval:    time.Duration(1),
			Timeout:     time.Duration(1), // clears state immediately
		},
		Jwt: config.Jwt{
			Context:        context.Background(),
			Logger:         log.New(),
			Allowed_scopes: []string{"scope1"},
			Included_paths: []string{},
		},
	}
}

func generateTestJWT(key jwk.Key, scope string, isExpired bool) (string, error) {
	claims := jwt.New()
	claims.Set(scope, []string{"scope1", "scope2", "scope3"})
	if isExpired {
		claims.Set(jwt.ExpirationKey, time.Now())
	} else {
		claims.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))
	}
	claims.Set(jwt.IssuerKey, "issuer")
	claims.Set(jwt.AudienceKey, "audience")
	claims.Set(jwt.NotBeforeKey, time.Now().Add(-1*time.Minute))
	claims.Set(jwt.IssuedAtKey, time.Now())
	claims.Set(jwt.JwtIDKey, "jti")

	token, err := jwt.Sign(claims, jwa.RS256, key)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func generateTestJWKSingleKey(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, keyID string) (jwk.Key, jwk.Set, error) {
	jwkKeySingle, _ := jwk.New(privateKey)
	jwkKeySingle.Set("kid", keyID)
	key, err := jwk.New(publicKey)
	if err != nil {
		return jwkKeySingle, nil, err
	}
	key.Set(jwk.KeyIDKey, keyID)
	key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	key.Set(jwk.AlgorithmKey, "RS256")
	jwks := jwk.NewSet()
	isAdded := jwks.Add(key)
	if !isAdded {
		return jwkKeySingle, nil, err
	}

	return jwkKeySingle, jwks, nil
}

func generateTestJWKMultipleKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, keyID string, numberOfMultiples int) (jwk.Key, jwk.Set, error) {
	jwkKeyMultiple, jwks, _ := generateTestJWKSingleKey(privateKey, publicKey, keyID)
	for i := 0; i < numberOfMultiples; i++ {
		newKey, err := jwk.New(publicKey)
		if err != nil {
			return jwkKeyMultiple, nil, err
		}
		newKey.Set(jwk.KeyIDKey, keyID+"."+strconv.Itoa(i+1))
		newKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
		newKey.Set(jwk.AlgorithmKey, "RS256")
		isAdded2 := jwks.Add(newKey)
		if !isAdded2 {
			return jwkKeyMultiple, nil, err
		}
	}

	return jwkKeyMultiple, jwks, nil
}

func generateTestKeysAndKeySets() (jwk.Key, jwk.Key, jwk.Set, jwk.Set) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	jwkKeySingle, jwkKeySetSingle, _ := generateTestJWKSingleKey(privateKey, publicKey, "key-id-single")
	jwkKeyMultiple, jwkKeySetMultiple, _ := generateTestJWKMultipleKeys(privateKey, publicKey, "key-id-multiple", 1)

	return jwkKeySingle, jwkKeyMultiple, jwkKeySetSingle, jwkKeySetMultiple
}

func createTestServer(t *testing.T, jsonJWKKeySetSingle []byte, jsonJWKKeySetMultiple []byte) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Got connection!")
		switch r.URL.String() {
		case "/.well-known-multiple/jwks.json":
			w.Write([]byte(jsonJWKKeySetMultiple))
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			break
		case "/.well-known-single/jwks.json":
			w.Write([]byte(jsonJWKKeySetSingle))
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			break

		case "/.bad-known/jwks.json":
			break
		default:
			t.Fatalf("Unknown request:" + r.URL.String())
		}
	}))

	return ts
}

// Tests
func TestAllowedScope(t *testing.T) {
	co := &config.Jwt{Allowed_scopes: []string{"admin"}}
	res := haveAllowedScope([]string{""}, co.Allowed_scopes)
	assert.Equal(t, res, false, "No scope provided, should be false")

	res = haveAllowedScope([]string{"admin"}, co.Allowed_scopes)
	assert.Equal(t, res, true, "Admin is provided and allowed, should be true")

	res = haveAllowedScope([]string{"admin"}, []string{})
	assert.Equal(t, res, false, "No allowed scopes, should be false")

	res = haveAllowedScope([]string{}, []string{})
	assert.Equal(t, res, false, "Empty scopes and empty allowed scopes, should be false")
}

func TestGetScopesWithScopeClaim(t *testing.T) {
	jwkKeySingle, _, _, _ := generateTestKeysAndKeySets()
	strExpiredToken, _ := generateTestJWT(jwkKeySingle, "scope", true)

	token, _ := jwt.ParseString(strExpiredToken, jwt.WithTypedClaim("scope", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestGetScopesWithScpClaim(t *testing.T) {
	jwkKeySingle, _, _, _ := generateTestKeysAndKeySets()
	scpClaimToken, _ := generateTestJWT(jwkKeySingle, "scp", true)
	token, _ := jwt.ParseString(scpClaimToken, jwt.WithTypedClaim("scp", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestValidateJWT(t *testing.T) {
	jwkKeySingle, jwkKeyMultiple, jwkKeySetSingle, jwkKeySetMultiple := generateTestKeysAndKeySets()
	scpExpiredToken, _ := generateTestJWT(jwkKeyMultiple, "scp", true)
	scopeGoodToken, _ := generateTestJWT(jwkKeySingle, "scope", false)
	scopeGoodTokenMultiple, _ := generateTestJWT(jwkKeyMultiple, "scope", false)
	scpGoodToken, _ := generateTestJWT(jwkKeySingle, "scp", false)
	jsonJWKKeySetSingle, _ := json.Marshal(jwkKeySetSingle)
	jsonJWKKeySetMultiple, _ := json.Marshal(jwkKeySetMultiple)
	ts := createTestServer(t, jsonJWKKeySetSingle, jsonJWKKeySetMultiple)
	defer ts.Close()

	// Test 1
	co = nil
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "No token provided status code should be 401")
	assert.Containsf(t, w.Body.String(), "failed to find a valid token in any location of the request", "No token provided status code should be 401")

	// Test 2
	config.Config.Jwt.Jwks_url = ts.URL + "/.bad-known/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "failed to fetch resource pointed by")
	assert.Containsf(t, w.Body.String(), "failed to fetch resource pointed by", "failed to fetch resource pointed by")

	// Test 3
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-multiple/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "exp not satisfied", "Token expired: exp not satisfied")

	// Test 4
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "Invalid Scope", "Invalid Scope")

	// Test 5
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// Test 6
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// Test 7
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-multiple/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodTokenMultiple)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")
}

func TestJWTMiddlewareValidatesWithNoToken(t *testing.T) {
	// TODO: Implement tags and uncomment initLogs()
	config.Config = getCommonConfig()
	config.Config.Jwt.Included_paths = []string{"/"}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJWTMiddlewareValidatesWithToken(t *testing.T) {
	// TODO: Implement tags and uncomment initLogs()
	config.Config = getCommonConfig()
	config.Config.Jwt.Included_paths = []string{"/"}
	jwkKeySingle, _, jwkKeySetSingle, jwkKeySetMultiple := generateTestKeysAndKeySets()
	token, _ := generateTestJWT(jwkKeySingle, "scp", false)
	jsonJWKKeySetSingle, _ := json.Marshal(jwkKeySetSingle)
	jsonJWKKeySetMultiple, _ := json.Marshal(jwkKeySetMultiple)
	ts := createTestServer(t, jsonJWKKeySetSingle, jsonJWKKeySetMultiple)
	defer ts.Close()
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	req.Header.Add("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJWTMiddlewareWithoutJWTValidation(t *testing.T) {
	// TODO: Implement tags and uncomment initLogs()
	config.Config = getCommonConfig()
	config.Config.Jwt.Included_paths = []string{}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	co = nil
	InitJWT(&config.Jwt{
		Context:        config.Config.Jwt.Context,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         config.Config.Jwt.Logger,
	})
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

// func TestJWTMiddlewareEndToEnd(t *testing.T) {
// 	req, _ := http.NewRequest("GET", "http://127.0.0.1:50080/", nil)

// 	res, err := http.DefaultClient.Do(req)

// 	assert.Nil(t, err)
// 	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
// }
