//go:build all || unit
// +build all unit

package jwt

//                                                                         __
// .-----.-----.______.-----.----.-----.--.--.--.--.______.----.---.-.----|  |--.-----.
// |  _  |  _  |______|  _  |   _|  _  |_   _|  |  |______|  __|  _  |  __|     |  -__|
// |___  |_____|      |   __|__| |_____|__.__|___  |      |____|___._|____|__|__|_____|
// |_____|            |__|                   |_____|
//
// Copyright (c) 2023 Fabio Cicerchia. https://fabiocicerchia.it. MIT License
// Repo: https://github.com/fabiocicerchia/go-proxy-cache

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/fabiocicerchia/go-proxy-cache/config"
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

func TestGetScopesWithScopeClaim(t *testing.T) {
	jwkKeySingle, _, _, _ := GenerateTestKeysAndKeySets()
	strExpiredToken, _ := GenerateTestJWT(jwkKeySingle, "scope", true)

	token, _ := jwt.ParseString(strExpiredToken, jwt.WithTypedClaim("scope", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestGetScopesWithScpClaim(t *testing.T) {
	jwkKeySingle, _, _, _ := GenerateTestKeysAndKeySets()
	scpClaimToken, _ := GenerateTestJWT(jwkKeySingle, "scp", true)
	token, _ := jwt.ParseString(scpClaimToken, jwt.WithTypedClaim("scp", json.RawMessage{}))

	res := getScopes(token)

	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope3"}, "Scopes provided doesn't match")
}

func TestValidateJWT(t *testing.T) {
	jwkKeySingle, jwkKeyMultiple, jsonJWKKeySetSingle, jsonJWKKeySetMultiple := GenerateTestKeysAndKeySets()
	scpExpiredToken, _ := GenerateTestJWT(jwkKeyMultiple, "scp", true)
	scopeGoodToken, _ := GenerateTestJWT(jwkKeySingle, "scope", false)
	scopeGoodTokenMultiple, _ := GenerateTestJWT(jwkKeyMultiple, "scope", false)
	scpGoodToken, _ := GenerateTestJWT(jwkKeySingle, "scp", false)
	ts := CreateTestServer(t, jsonJWKKeySetSingle, jsonJWKKeySetMultiple)
	defer ts.Close()

	// Without any token
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "No token provided status code should be 401")
	assert.Containsf(t, w.Body.String(), "failed to find a valid token in any location of the request", "No token provided status code should be 401")

	// Without any keyset
	config.Config.Jwt.Jwks_url = ts.URL + "/.bad-known/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "failed to fetch resource pointed by")
	assert.Containsf(t, w.Body.String(), "failed to fetch resource pointed by", "failed to fetch resource pointed by")

	// With an expired token
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-multiple/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpExpiredToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "exp not satisfied")
	assert.Containsf(t, w.Body.String(), "exp not satisfied", "Token expired: exp not satisfied")

	// Without any scope in the config
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 401, "Invalid Scope")
	assert.Containsf(t, w.Body.String(), "Invalid Scope", "Invalid Scope")

	// With a scope in the config and a valid token (with scope claim)
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// With a scope in the config and a valid token (with scp claim)
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-single/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scpGoodToken)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")

	// With multiple keys in the key set
	config.Config.Jwt.Jwks_url = ts.URL + "/.well-known-multiple/jwks.json"
	config.Config.Jwt.Allowed_scopes = []string{"scope1"}
	co = nil
	InitJWT(&config.Jwt{
		Included_paths: config.Config.Jwt.Included_paths,
		Allowed_scopes: config.Config.Jwt.Allowed_scopes,
		Jwks_url:       config.Config.Jwt.Jwks_url,
		Context:        context.Background(),
		Logger:         log.New(),
	})
	req = httptest.NewRequest("GET", "http://example.com/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+scopeGoodTokenMultiple)

	ValidateJWT(w, req)

	assert.Equal(t, w.Code, 200, "Status OK")
	assert.Containsf(t, w.Body.String(), "", "Status OK")
}