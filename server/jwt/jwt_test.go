package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	logger "github.com/fabiocicerchia/go-proxy-cache/logger"
	"github.com/stretchr/testify/assert"
)

func TestAllowedScope(t *testing.T) {
	co := &JwtConfig{Allowed_scopes: []string{"admin"}}
	res := haveAllowedScope([]string{""}, co.Allowed_scopes)
	assert.Equal(t, res, false, "No scope provided, should be false")

	res = haveAllowedScope([]string{"admin"}, co.Allowed_scopes)
	assert.Equal(t, res, true, "Admin is provided and allowed, should be true")

	res = haveAllowedScope([]string{"admin"}, []string{})
	assert.Equal(t, res, false, "No allowed scopes, should be false")

	res = haveAllowedScope([]string{}, []string{})
	assert.Equal(t, res, false, "Empty scopes and empty allowed scopes, should be false")
}

const strExpiredToken = "expiredToken"
const strGoodToken = "goodToken"

func TestGetScopes(t *testing.T) {

	token, _ := jwt.ParseString(strExpiredToken, jwt.WithTypedClaim("scope", json.RawMessage{}))
	res := getScopes(token)
	assert.ElementsMatch(t, res, []string{"scope1", "scope2", "scope2", "scope4"}, "Scopes provided doesn't match")

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

	InitJWT(&JwtConfig{
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
	InitJWT(&JwtConfig{
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
	InitJWT(&JwtConfig{
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
	InitJWT(&JwtConfig{
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

func TestJWTMiddleware(t *testing.T) {

	// h := httptest.NewRecorder()

	// server := &http.Server{
    //     Addr:    "127.0.0.1:50080",
    //     Handler: JwtHandler(tracing.HTTPHandlerFunc(handler.HandleRequest, "handle_request")),
    // }
	//defer server.Close()

	req, err := http.NewRequest("GET", "http://127.0.0.1:50080", nil)


	// server.Handler.ServeHTTP(h, req)

	// Hacemos una solicitud HTTP GET al servidor de prueba
	if err != nil {
		t.Fatal(err)
	}

	// Añadimos un token JWT válido al encabezado Authorization
	// req.Header.Add("Authorization", "Bearer tu_token_jwt_valido")

	// Realizamos la solicitud
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Verificamos que la respuesta sea 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Esperaba un código de estado 200, pero obtuve %d", resp.StatusCode)
	}
	assert.Equal(t, 200, resp.StatusCode)
}
