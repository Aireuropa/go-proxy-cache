package jwt

import (
	"context"
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
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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

const strExpiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkaWVuY2Vfa2V5X3Rlc3QiXSwiZXhwIjoxNzAxOTg1Njk5LCJpYXQiOjE3MDE5ODIwOTksImlzcyI6Imlzc3Vlcl90ZXN0IiwianRpIjoidG9rZW5fdGVzdCIsIm5iZiI6MTcwMTk4MjAzOX0.v22O91_WLqEM6D6gtrANR5TchvQa8rWbZyz726VKk1s"
const strGoodToken = "goodToken"

func TestGetScopes(t *testing.T) {

	// Replace tokenWithScopes with a full token
	tokenWithScopes, _ := CreateJwt([]byte("secret_test"))
	token, _ := jwt.ParseString(tokenWithScopes, jwt.WithTypedClaim("scope", json.RawMessage{}))
	res := getScopes(token)
	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestValidateJwt(t *testing.T) {
	// Http server test
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Got connection!")
		switch r.URL.String() {
		case "/.well-known-test/jwks.json":
			fmt.Fprintln(w, `token-data`)
			break
		case "/.well-known/jwks.json":
			fmt.Fprintln(w, `token-data`)
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

	InitJwt(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.bad-known/jwks.json",
	})

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()
	Validate_jwt(w, req)
	assert.Equal(t, w.Code, 401, "No token provided status code should be 401")
	assert.Containsf(t, w.Body.String(), "failed to find a valid token in any location of the request", "No token provided status code should be 401")

	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+strExpiredToken)
	Validate_jwt(w, req)
	assert.Equal(t, w.Code, 401, "invalid JWK set passed via WithKeySet")
	assert.Containsf(t, w.Body.String(), "invalid JWK set passed via WithKeySet", "invalid JWK set passed via WithKeySet")

	co = nil
	InitJwt(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.well-known-test/jwks.json",
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+strExpiredToken)
	Validate_jwt(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "exp not satisfied", "Token expired: exp not satisfied")

	co = nil
	InitJwt(&config.Jwt{
		Context:  c,
		Logger:   l,
		Jwks_url: ts.URL + "/.well-known/jwks.json",
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+strGoodToken)
	Validate_jwt(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "Invalid Scope", "Invalid Scope")

	co = nil
	InitJwt(&config.Jwt{
		Context:        c,
		Logger:         l,
		Jwks_url:       ts.URL + "/.well-known/jwks.json",
		Allowed_scopes: []string{"scope1"},
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+strGoodToken)
	Validate_jwt(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

}

func TestJwtMiddlewareValidatesWithNoToken(t *testing.T) {
	// initLogs()

	config.Config = config.Configuration{
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
			Included_paths: []string{"/"},
			Logger:         log.New(),
		},
	}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	InitJwt(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	h := JwtHandler(muxMiddleware)
	
	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJwtMiddlewareValidatesWithToken(t *testing.T) {
	// initLogs()

	config.Config = config.Configuration{
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
			Included_paths: []string{"/"},
			Logger:         log.New(),
		},
	}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)
	
	token, _ := CreateJwt([]byte("secret_test"))
	req.Header.Add("Authorization", "Bearer " + token)

	InitJwt(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	h := JwtHandler(muxMiddleware)
	
	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJwtMiddlewareWithoutJwtValidation(t *testing.T) {
	// initLogs()

	config.Config = config.Configuration{
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
		},
	}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	InitJwt(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	timeout := config.Config.Server.Timeout
	if true {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	h := JwtHandler(muxMiddleware)
	
	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJwtMiddlewareWithoutJwtAndTimeoutValidation(t *testing.T) {
	// initLogs()

	config.Config = config.Configuration{
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
		},
	}

	domainID := config.Config.Server.Upstream.GetDomainID()
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	InitJwt(&config.Jwt{
		Context:        context.Background(),
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Included_paths: config.Config.Jwt.Included_paths,
		Logger:         log.New(),
	})

	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	timeout := config.Config.Server.Timeout
	if false {
		muxMiddleware = http.TimeoutHandler(muxMiddleware, timeout.Handler, "Timed Out\n")
	}
	h := JwtHandler(muxMiddleware)
	
	h.ServeHTTP(rr, req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)

	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())
}

func TestJwtMiddlewareEndToEnd(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://127.0.0.1:50080/", nil)

	res, err := http.DefaultClient.Do(req)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}
