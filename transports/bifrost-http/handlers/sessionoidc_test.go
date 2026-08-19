package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configtables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type oidcSessionStore struct {
	configstore.ConfigStore
	authConfig *configstore.AuthConfig
	sessions   map[string]*configtables.SessionsTable
}

func (s *oidcSessionStore) GetAuthConfig(context.Context) (*configstore.AuthConfig, error) {
	return s.authConfig, nil
}

func (s *oidcSessionStore) CreateSession(_ context.Context, session *configtables.SessionsTable) error {
	if s.sessions == nil {
		s.sessions = map[string]*configtables.SessionsTable{}
	}
	copy := *session
	s.sessions[session.Token] = &copy
	return nil
}

func (s *oidcSessionStore) GetSession(_ context.Context, token string) (*configtables.SessionsTable, error) {
	session := s.sessions[token]
	if session == nil {
		return nil, configstore.ErrNotFound
	}
	copy := *session
	return &copy, nil
}

func TestSessionOIDCStartRedirectsToDiscoveredAuthorizeEndpoint(t *testing.T) {
	idp, _ := newTestOIDCProvider(t, func() string { return "" })
	h := &SessionHandler{configStore: &oidcSessionStore{authConfig: testOIDCAuthConfig(idp.URL)}}
	ctx := getCtx("http://bifrost.local/api/session/sso/start?goto=/workspace/providers")

	h.startOIDCLogin(ctx)

	require.Equal(t, fasthttp.StatusFound, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	location := string(ctx.Response.Header.Peek("Location"))
	require.NotEmpty(t, location)
	authorizeURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, idp.URL, authorizeURL.Scheme+"://"+authorizeURL.Host)
	assert.Equal(t, "/authorize", authorizeURL.Path)
	query := authorizeURL.Query()
	assert.Equal(t, "client-id", query.Get("client_id"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.Equal(t, "openid profile email", query.Get("scope"))
	assert.Equal(t, "http://bifrost.local/api/session/sso/callback", query.Get("redirect_uri"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.NotEmpty(t, query.Get("state"))
	assert.NotEmpty(t, query.Get("nonce"))
	assert.NotEmpty(t, query.Get("code_challenge"))
	assert.Contains(t, string(ctx.Response.Header.Peek("Set-Cookie")), oidcLoginCookieName+"=")
	assert.Contains(t, string(ctx.Response.Header.Peek("Set-Cookie")), "HttpOnly")
}

func TestSessionOIDCCallbackCreatesBifrostSessionCookie(t *testing.T) {
	var nonce string
	idp, _ := newTestOIDCProvider(t, func() string { return nonce })
	store := &oidcSessionStore{authConfig: testOIDCAuthConfig(idp.URL)}
	h := &SessionHandler{configStore: store}

	startCtx := getCtx("http://bifrost.local/api/session/sso/start?goto=/workspace/providers")
	h.startOIDCLogin(startCtx)
	require.Equal(t, fasthttp.StatusFound, startCtx.Response.StatusCode(), string(startCtx.Response.Body()))

	loginCookie := parseSetCookie(t, startCtx, oidcLoginCookieName)
	pending, err := openOIDCLoginCookie(loginCookie, store.authConfig.OIDC.ClientSecret.GetValue())
	require.NoError(t, err)
	nonce = pending.Nonce

	callbackCtx := getCtx("http://bifrost.local/api/session/sso/callback?code=auth-code&state=" + url.QueryEscape(pending.State))
	callbackCtx.Request.Header.SetCookie(oidcLoginCookieName, loginCookie)

	h.completeOIDCLogin(callbackCtx)

	require.Equal(t, fasthttp.StatusFound, callbackCtx.Response.StatusCode(), string(callbackCtx.Response.Body()))
	assert.Equal(t, "/workspace/providers", string(callbackCtx.Response.Header.Peek("Location")))
	sessionToken := parseSetCookie(t, callbackCtx, "token")
	assert.NotEmpty(t, sessionToken)
	session, err := store.GetSession(context.Background(), sessionToken)
	require.NoError(t, err)
	assert.True(t, session.ExpiresAt.After(time.Now()))
	assert.Contains(t, string(callbackCtx.Response.Header.Peek("Set-Cookie")), "HttpOnly")
}

func TestSessionOIDCCallbackFallsBackForUnsafeGoto(t *testing.T) {
	var nonce string
	idp, _ := newTestOIDCProvider(t, func() string { return nonce })
	store := &oidcSessionStore{authConfig: testOIDCAuthConfig(idp.URL)}
	h := &SessionHandler{configStore: store}

	startCtx := getCtx("http://bifrost.local/api/session/sso/start?goto=https%3A%2F%2Fevil.example.com")
	h.startOIDCLogin(startCtx)
	require.Equal(t, fasthttp.StatusFound, startCtx.Response.StatusCode(), string(startCtx.Response.Body()))

	loginCookie := parseSetCookie(t, startCtx, oidcLoginCookieName)
	pending, err := openOIDCLoginCookie(loginCookie, store.authConfig.OIDC.ClientSecret.GetValue())
	require.NoError(t, err)
	nonce = pending.Nonce

	callbackCtx := getCtx("http://bifrost.local/api/session/sso/callback?code=auth-code&state=" + url.QueryEscape(pending.State))
	callbackCtx.Request.Header.SetCookie(oidcLoginCookieName, loginCookie)

	h.completeOIDCLogin(callbackCtx)

	require.Equal(t, fasthttp.StatusFound, callbackCtx.Response.StatusCode(), string(callbackCtx.Response.Body()))
	assert.Equal(t, "/workspace", string(callbackCtx.Response.Header.Peek("Location")))
}

func TestSessionOIDCCallbackRejectsEmailOutsideAllowlist(t *testing.T) {
	var nonce string
	idp, _ := newTestOIDCProvider(t, func() string { return nonce }, withOIDCEmail("intruder@example.com"))
	store := &oidcSessionStore{authConfig: testOIDCAuthConfig(idp.URL)}
	h := &SessionHandler{configStore: store}

	startCtx := getCtx("http://bifrost.local/api/session/sso/start")
	h.startOIDCLogin(startCtx)
	require.Equal(t, fasthttp.StatusFound, startCtx.Response.StatusCode(), string(startCtx.Response.Body()))

	loginCookie := parseSetCookie(t, startCtx, oidcLoginCookieName)
	pending, err := openOIDCLoginCookie(loginCookie, store.authConfig.OIDC.ClientSecret.GetValue())
	require.NoError(t, err)
	nonce = pending.Nonce

	callbackCtx := getCtx("http://bifrost.local/api/session/sso/callback?code=auth-code&state=" + url.QueryEscape(pending.State))
	callbackCtx.Request.Header.SetCookie(oidcLoginCookieName, loginCookie)

	h.completeOIDCLogin(callbackCtx)

	require.Equal(t, fasthttp.StatusForbidden, callbackCtx.Response.StatusCode())
	assert.Empty(t, store.sessions)
}

func TestSessionLoginRejectsPasswordWhenOIDCEnabled(t *testing.T) {
	h := &SessionHandler{configStore: &oidcSessionStore{authConfig: testOIDCAuthConfig("https://idp.example.com")}}
	ctx := getCtx("http://bifrost.local/api/session/login")
	ctx.Request.SetBodyString(`{"username":"admin","password":"password"}`)

	h.login(ctx)

	require.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), "use SSO")
}

func TestDashboardAuthTypeReportsOIDCWhenConfigured(t *testing.T) {
	authConfig := testOIDCAuthConfig("https://idp.example.com")

	assert.Equal(t, "oidc", dashboardAuthType(authConfig))
}

func testOIDCAuthConfig(issuerURL string) *configstore.AuthConfig {
	return &configstore.AuthConfig{
		IsEnabled: true,
		AuthType:  configstore.AuthTypeOIDC,
		OIDC: &configstore.OIDCAuthConfig{
			IssuerURL:           issuerURL,
			ClientID:            "client-id",
			ClientSecret:        schemas.NewSecretVar("client-secret"),
			RedirectURL:         "http://bifrost.local/api/session/sso/callback",
			Scopes:              []string{"openid", "profile", "email"},
			AllowedEmailDomains: []string{"thoughtspot.com"},
		},
	}
}

type testOIDCProviderOption func(*testOIDCProviderState)

type testOIDCProviderState struct {
	email string
}

func withOIDCEmail(email string) testOIDCProviderOption {
	return func(state *testOIDCProviderState) {
		state.email = email
	}
}

func newTestOIDCProvider(t *testing.T, nonce func() string, opts ...testOIDCProviderOption) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	_, privateKey := newTestSigningKey(t)
	state := &testOIDCProviderState{email: "deepak@thoughtspot.com"}
	for _, opt := range opts {
		opt(state)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/jwks",
			})
		case "/jwks":
			writeJSON(t, w, map[string]any{
				"keys": []map[string]any{rsaPublicKeyToJWK("test-kid", "RS256", &privateKey.PublicKey)},
			})
		case "/token":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
			assert.Equal(t, "auth-code", r.Form.Get("code"))
			assert.NotEmpty(t, r.Form.Get("code_verifier"))
			writeJSON(t, w, map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     mintOIDCIDToken(t, privateKey, server.URL, nonce(), state.email),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, privateKey
}

func mintOIDCIDToken(t *testing.T, privateKey *rsa.PrivateKey, issuer, nonce, email string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"aud":   "client-id",
		"sub":   "user-1",
		"email": email,
		"nonce": nonce,
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	})
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}

func parseSetCookie(t *testing.T, ctx *fasthttp.RequestCtx, name string) string {
	t.Helper()
	rawCookie := string(ctx.Response.Header.PeekCookie(name))
	if rawCookie != "" {
		cookie := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(cookie)
		require.NoError(t, cookie.Parse(rawCookie))
		if string(cookie.Key()) == name {
			value := string(cookie.Value())
			require.NotEmpty(t, value)
			return value
		}
	}
	t.Fatalf("missing Set-Cookie %s in %q", name, string(ctx.Response.Header.Peek("Set-Cookie")))
	return ""
}
