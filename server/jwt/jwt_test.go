package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	math "math/rand"
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
	claims.Set(jwt.AudienceKey, "audience_key")
	claims.Set(jwt.NotBeforeKey, time.Now().Add(-1*time.Minute))
	claims.Set(jwt.IssuedAtKey, time.Now())
	claims.Set(jwt.JwtIDKey, "key-jti-1")
	
	token, err := jwt.Sign(claims, jwa.RS256, key)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func generateTestJWKSingleKey(publicKey *rsa.PublicKey, keyID string) (jwk.Set, error) {
    key, err := jwk.New(publicKey)
    if err != nil {
        return nil, err
    }
    key.Set(jwk.KeyIDKey, keyID)
    key.Set(jwk.KeyUsageKey, jwk.ForSignature)
    key.Set(jwk.AlgorithmKey, "RS256")
    jwks := jwk.NewSet()
	isAdded := jwks.Add(key)
	if (!isAdded) {
		return nil, nil
	}

    return jwks, nil
}

func generateTestJWKMultipleKeys(publicKey *rsa.PublicKey, keyID string) (jwk.Set, error) {

	key1, err := jwk.New(publicKey)
    if err != nil {
        return nil, err
    }
    key1.Set(jwk.KeyIDKey, keyID)
    key1.Set(jwk.KeyUsageKey, jwk.ForSignature)
    key1.Set(jwk.AlgorithmKey, "RS256")
    jwks := jwk.NewSet()
	isAdded := jwks.Add(key1)
	if (!isAdded) {
		return nil, nil
	}

	key2, err := jwk.New(publicKey)
    if err != nil {
        return nil, err
    }
    key2.Set(jwk.KeyIDKey, keyID+"-"+strconv.Itoa(generateRandomNumber()))
    key2.Set(jwk.KeyUsageKey, jwk.ForSignature)
    key2.Set(jwk.AlgorithmKey, "RS256")
	isAdded2 := jwks.Add(key2)
	if (!isAdded2) {
		return nil, nil
	}

    return jwks, nil
}

func generateRandomNumber() int {
	r := math.New(math.NewSource(time.Now().UnixNano()))
    var ale int
    for f := 0; f < 1; f++ {
        ale = r.Intn(1000000)
    }
	return ale
}

func generateKeys() (jwk.Key, jwk.Key, jwk.Set, jwk.Set, ) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	jwkKeyA, _ := jwk.New(privateKey)
	keyIdA := "key-id-1"
	jwkKeyA.Set("kid", keyIdA)
	jwkKeySetSingle, _  := generateTestJWKSingleKey(publicKey, keyIdA)

	jwkKeyB, _ := jwk.New(privateKey)
	keyIdB := "key-id-1-test"
	jwkKeyB.Set("kid", "key-id-1-test")
	jwkKeySetMultiple, _  := generateTestJWKMultipleKeys(publicKey, keyIdB)

	return jwkKeyA, jwkKeyB, jwkKeySetSingle, jwkKeySetMultiple
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
		case "/.well-known/jwks.json":
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
	jwkKey, _, _, _ := generateKeys()
	strExpiredToken, _ := generateTestJWT(jwkKey, "scope", true)

	token, _ := jwt.ParseString(strExpiredToken, jwt.WithTypedClaim("scope", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestGetScopesWithScpClaim(t *testing.T) {
	jwkKey, _, _, _ := generateKeys()
	scpClaimToken, _ := generateTestJWT(jwkKey, "scp", true)
	token, _ := jwt.ParseString(scpClaimToken, jwt.WithTypedClaim("scp", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestValidateJWT(t *testing.T) {
	jwkKeyA, jwkKeyB, jwkKeySetSingle, jwkKeySetMultiple := generateKeys()
	scpExpiredToken, _ := generateTestJWT(jwkKeyB, "scp", true)
	scopeGoodToken, _ := generateTestJWT(jwkKeyA, "scope", false)
	scpGoodToken, _ := generateTestJWT(jwkKeyA, "scp", false)
	jsonJWKKeySetSingle, _ := json.Marshal(jwkKeySetSingle)
	jsonJWKKeySetMultiple, _ := json.Marshal(jwkKeySetMultiple)
	ts := createTestServer(t, jsonJWKKeySetSingle, jsonJWKKeySetMultiple)
	defer ts.Close()

	// Test 1
	co = nil
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known/jwks.json"
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
	config.Config.Jwt.Jwks_url = ts.URL+"/.bad-known/jwks.json"
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
	req.Header.Add("Authorization", "Bearer "+ scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "failed to fetch resource pointed by")
	assert.Containsf(t, w.Body.String(), "failed to fetch resource pointed by", "failed to fetch resource pointed by")

	// Test 3
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known-multiple/jwks.json"
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
	req.Header.Add("Authorization", "Bearer "+ scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "exp not satisfied", "Token expired: exp not satisfied")

	// Test 4
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known/jwks.json"
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
	req.Header.Add("Authorization", "Bearer "+ scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "Invalid Scope", "Invalid Scope")

	// Test 5
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known/jwks.json"
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
	req.Header.Add("Authorization", "Bearer "+ scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// Test 6
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known/jwks.json"
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
	req.Header.Add("Authorization", "Bearer "+ scpGoodToken)

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
	jwkKey, _, jwksKeySet, testJwksKeySet := generateKeys()
	token, _ := generateTestJWT(jwkKey, "scp", false)
	jsonJWKSKeySet, _ := json.Marshal(jwksKeySet)
	testJsonJWKSKeySet, _ := json.Marshal(testJwksKeySet)
	ts := createTestServer(t, jsonJWKSKeySet, testJsonJWKSKeySet)
	defer ts.Close()
	config.Config.Jwt.Jwks_url = ts.URL+"/.well-known/jwks.json"

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

func TestJWTMiddlewareEndToEnd(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://127.0.0.1:50080/", nil)

	res, err := http.DefaultClient.Do(req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
