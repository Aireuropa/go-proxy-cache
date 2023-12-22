package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// jwt.KeySetProviderFunc()

// type Key struct {
// 	Kid string `json:"kid"`
// 	Kty string `json:"kty"`
// 	Use string `json:"use"`
// 	N   string `json:"n"`
// 	E   string `json:"e"`
// }

// type JWKS struct {
// 	Keys []Key `json:"keys"`
// }

// type jwkKey struct {
// 	Kid   string `json:"kid"`
// 	Kty   string `json:"kty"`
// 	N     string `json:"n"`
// 	E     string `json:"e"`
// 	Alg   string `json:"alg"`
// 	Use   string `json:"use"`
// 	Certs string `json:"x5c,omitempty"`
// }

// Creation JWTs
func CreateJWTTestWithScopeClaim(key jwk.Key) (string, error) {
	claims := jwt.New()
	claims.Set("scope", []string{"scope1", "scope2", "scope3"})
	claims.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))
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

func CreateJWTTestWithScpClaim(key jwk.Key) (string, error) {
	claims := jwt.New()
	claims.Set("scp", []string{"scope1", "scope2", "scope3"})
	claims.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))
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

func CreateJWTTestWithScpClaimExpired(key jwk.Key) (string, error) {
	claims := jwt.New()
	claims.Set("scp", []string{"scope1", "scope2", "scope3"})
	claims.Set(jwt.ExpirationKey, time.Now())
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

// Creation JWKs
func generateJWKS(publicKey *rsa.PublicKey, keyID string) (jwk.Set, error) {
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

func generateJWKSTest(publicKey *rsa.PublicKey, keyID string) (jwk.Set, error) {
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

	// key2, err := jwk.New(publicKey)
    // if err != nil {
    //     return nil, err
    // }
    // key2.Set(jwk.KeyIDKey, keyID)
    // key2.Set(jwk.KeyUsageKey, jwk.ForSignature)
    // key2.Set(jwk.AlgorithmKey, "RS256")
	// isAdded2 := jwks.Add(key2)
	// if (!isAdded2) {
	// 	return nil, nil
	// }

    return jwks, nil
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
	_, _, jwkKey, _, _ := generateKeys()
	strExpiredToken, _ := CreateJWTTestWithScpClaimExpired(jwkKey)

	token, _ := jwt.ParseString(strExpiredToken, jwt.WithTypedClaim("scope", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestGetScopesWithScpClaim(t *testing.T) {
	_, _, jwkKey, _, _ := generateKeys()
	scpClaimToken, _ := CreateJWTTestWithScpClaim(jwkKey)
	token, _ := jwt.ParseString(scpClaimToken, jwt.WithTypedClaim("scp", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey, jwk.Key, jwk.Set, jwk.Set) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	jwkKey, _ := jwk.New(privateKey)
	jwkKey.Set("kid", "key-id-1-test")
	jwks, _  := generateJWKS(publicKey, "key-id-1")
	testJwks, _  := generateJWKSTest(publicKey, "key-id-1-test")
	
	return privateKey, publicKey, jwkKey, jwks, testJwks
}

func TestValidateJWT(t *testing.T) {
	_, _, jwkKey, jwks, _ := generateKeys()
	_, _, _, _, testJwks := generateKeys()

	strExpiredToken, _ := CreateJWTTestWithScpClaimExpired(jwkKey)
	scopeGoodToken, _ := CreateJWTTestWithScopeClaim(jwkKey)
	scpGoodToken, _ := CreateJWTTestWithScpClaim(jwkKey)

	jsonJWKS, _ := json.Marshal(jwks)
	testJsonJWKS, _ := json.Marshal(testJwks)
	// Http server test
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Got connection!")
		switch r.URL.String() {
		case "/.well-known-test/jwks.json":
			w.Write([]byte(testJsonJWKS))
			w.WriteHeader(http.StatusOK)
			fmt.Print("errer", w)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w)	
			break
		case "/.well-known/jwks.json":
			w.Write([]byte(jsonJWKS))
			w.WriteHeader(http.StatusOK)
			fmt.Print("errer", w)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w)			
			break

		case "/.bad-known/jwks.json":
			break
		default:
			t.Fatalf("Unknown request:" + r.URL.String())
		}

	}))
	defer ts.Close()

	co = nil

	c := context.Background()
	l := logger.GetGlobal()

	// Test 1
	InitJWT(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.well-known/jwks.json",
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "No token provided status code should be 401")
	assert.Containsf(t, w.Body.String(), "failed to find a valid token in any location of the request", "No token provided status code should be 401")

	// Test 2
	co = nil
	InitJWT(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.bad-known/jwks.json",
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+ strExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "failed to fetch resource pointed by")
	assert.Containsf(t, w.Body.String(), "failed to fetch resource pointed by", "failed to fetch resource pointed by")

	// Test 3
	co = nil
	InitJWT(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.well-known-test/jwks.json",
	})

	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+ strExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "exp not satisfied", "Token expired: exp not satisfied")

	// Test 4
	co = nil
	InitJWT(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.well-known/jwks.json",
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+ scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "Invalid Scope", "Invalid Scope")

	// Test 5
	co = nil
	InitJWT(&config.Jwt{
		Context:        c,
		Logger:         l,
		Jwks_url:       ts.URL + "/.well-known/jwks.json",
		Allowed_scopes: []string{"scope1"},
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+ scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// Test 6
	co = nil
	InitJWT(&config.Jwt{
		Context:        c,
		Logger:         l,
		Jwks_url:       ts.URL + "/.well-known/jwks.json",
		Allowed_scopes: []string{"scope1"},
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+ scpGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")
}

func TestJWTMiddlewareValidatesWithNoToken(t *testing.T) {
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
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	InitJWT(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
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

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	_, _, jwkKey, _, _ := generateKeys()
	token, _ := CreateJWTTestWithScpClaimExpired(jwkKey)
	req.Header.Add("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	InitJWT(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

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
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	InitJWT(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJWTMiddlewareWithoutJWTAndTimeoutValidation(t *testing.T) {
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
	timeout := config.Config.Server.Timeout
	if false {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	InitJWT(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
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
