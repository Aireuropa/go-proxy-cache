package jwt

// TODO: Add ascii art

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fabiocicerchia/go-proxy-cache/cache/engine"
	"github.com/fabiocicerchia/go-proxy-cache/config"
	logger "github.com/fabiocicerchia/go-proxy-cache/logger"
	"github.com/fabiocicerchia/go-proxy-cache/server/balancer"
	"github.com/fabiocicerchia/go-proxy-cache/server/handler"
	"github.com/fabiocicerchia/go-proxy-cache/telemetry/tracing"
	circuit_breaker "github.com/fabiocicerchia/go-proxy-cache/utils/circuit-breaker"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHTTPEndToEndCallWithoutCacheWithJWTValidation(t *testing.T) {
	// TestHTTPEndToEndCallWithoutCacheWithJWTValidationPerDomain
	config.Config = config.Configuration{
		Server: config.Server{
			Upstream: config.Upstream{
				Host:      "example.com",
				Scheme:    "https",
			},
		},
		CircuitBreaker: circuit_breaker.CircuitBreaker{
			Threshold:   2,                // after 2nd request, if meet FailureRate goes open.
			FailureRate: 0.5,              // 1 out of 2 fails, or more
			Interval:    time.Duration(1), // clears counts immediately
			Timeout:     time.Duration(1), // clears state immediately
		},
	}
	config.Config.Domains = make(config.Domains)
	domainConf := config.Config
	domainConf.Jwt.Included_paths = []string{"/"}
	config.Config.Domains["example_com"] = domainConf

	domainID := config.Config.Server.Upstream.GetDomainID()
	balancer.InitRoundRobin(domainID, config.Config.Server.Upstream, false)
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())

	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)
	req.URL.Scheme = config.Config.Server.Upstream.Scheme
	req.URL.Host = config.Config.Server.Upstream.Host
	req.Host = config.Config.Server.Upstream.Host
	req.TLS = &tls.ConnectionState{} // mock a fake https
	assert.Nil(t, err)
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// TestHTTPEndToEndCallWithoutCacheWithoutJWTValidationPerDomain
	domainConf = config.Config
	domainConf.Jwt.Included_paths = nil
	config.Config.Domains["example_com"] = domainConf
	config.Config.Jwt.Included_paths = []string{"/"}
	
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// TestHTTPEndToEndCallWithoutCacheWithJWTValidationWithoutDomain
	domainConf = config.Config
	config.Config.Jwt.Included_paths = []string{"/"}
	config.Config.Domains = make(map[string]config.Configuration)
	
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	tearDownHTTPFunctional()
}

func TestHTTPEndToEndCallWithoutCacheWithJWTConfig(t *testing.T) {
	// TestHTTPEndToEndCallWithoutCacheWithJWTConfigPerDomain
	config.Config = config.Configuration{
		Server: config.Server{
			Upstream: config.Upstream{
				Host:      "example.com",
				Scheme:    "https",
			},
		},
		CircuitBreaker: circuit_breaker.CircuitBreaker{
			Threshold:   2,                // after 2nd request, if meet FailureRate goes open.
			FailureRate: 0.5,              // 1 out of 2 fails, or more
			Interval:    time.Duration(1), // clears counts immediately
			Timeout:     time.Duration(1), // clears state immediately
		},
	}

	domainID := config.Config.Server.Upstream.GetDomainID()
	balancer.InitRoundRobin(domainID, config.Config.Server.Upstream, false)
	circuit_breaker.InitCircuitBreaker(domainID, config.Config.CircuitBreaker, logger.GetGlobal())
	engine.InitConn(domainID, config.Config.Cache, log.StandardLogger())

	engine.GetConn(domainID).Close()

	req, err := http.NewRequest("GET", "/", nil)

	jwkKeySingle, _, jsonJWKKeySetSingle, jsonJWKKeySetMultiple := GenerateTestKeysAndKeySets()
	token, _ := GenerateTestJWT(jwkKeySingle, "scope", false)
	req.Header.Add("Authorization", "Bearer "+token)
	ts := CreateTestServer(t, jsonJWKKeySetSingle, jsonJWKKeySetMultiple)
	defer ts.Close()

	config.Config.Domains = make(config.Domains)
	domainConf := config.Config
	domainConf.Jwt.Included_paths = []string{"/"}
	domainConf.Jwt.Allowed_scopes = []string{"scope1", "scope2"}
	domainConf.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Domains["example_com"] = domainConf

	req.URL.Scheme = config.Config.Server.Upstream.Scheme
	req.URL.Host = config.Config.Server.Upstream.Host
	req.Host = config.Config.Server.Upstream.Host
	req.TLS = &tls.ConnectionState{} // mock a fake https
	assert.Nil(t, err)
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/", tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request"))
	var muxMiddleware http.Handler = mux
	h := JWTHandler(muxMiddleware)

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "MISS", rr.HeaderMap["X-Go-Proxy-Cache-Status"][0])

	// TestHTTPEndToEndCallWithoutCacheWithoutJWTConfigPerDomain
	domainConf = config.Config
	domainConf.Jwt.Included_paths = nil
	domainConf.Jwt.Allowed_scopes = nil
	domainConf.Jwt.Jwks_url = ""
	config.Config.Domains["example_com"] = domainConf
	config.Config.Jwt.Included_paths = []string{"/"}
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "MISS", rr.HeaderMap["X-Go-Proxy-Cache-Status"][0])

	// TestHTTPEndToEndCallWithoutCacheWithJWTConfigWithoutDomain
	domainConf = config.Config
	config.Config.Jwt.Included_paths = []string{"/"}
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Domains = make(map[string]config.Configuration)

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "MISS", rr.HeaderMap["X-Go-Proxy-Cache-Status"][0])

	tearDownHTTPFunctional()
}

func tearDownHTTPFunctional() {
	config.Config = config.Configuration{}
}