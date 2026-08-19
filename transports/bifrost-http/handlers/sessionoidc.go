package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/valyala/fasthttp"
	"golang.org/x/oauth2"
)

const (
	oidcLoginCookieName = "bifrost_oidc_login"
	oidcLoginTTL        = 10 * time.Minute
)

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcLoginCookie struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Goto         string `json:"goto"`
	ExpiresAt    int64  `json:"expires_at"`
}

type oidcClaims struct {
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

func (h *SessionHandler) startOIDCLogin(ctx *fasthttp.RequestCtx) {
	authConfig, err := h.getEnabledOIDCAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusForbidden, err.Error())
		return
	}
	discovery, _, err := discoverOIDC(ctx, authConfig.OIDC.IssuerURL)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Failed to discover OIDC provider: %v", err))
		return
	}
	state, err := randomURLSafe(32)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to start SSO login")
		return
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to start SSO login")
		return
	}
	codeVerifier, err := randomURLSafe(64)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to start SSO login")
		return
	}
	redirectURL := oidcRedirectURL(ctx, authConfig.OIDC)
	pending := oidcLoginCookie{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Goto:         safeDashboardGoto(string(ctx.QueryArgs().Peek("goto"))),
		ExpiresAt:    time.Now().Add(oidcLoginTTL).Unix(),
	}
	cookieValue, err := sealOIDCLoginCookie(pending, authConfig.OIDC.ClientSecret.GetValue())
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to start SSO login")
		return
	}
	setOIDCLoginCookie(ctx, cookieValue, time.Now().Add(oidcLoginTTL))

	oauthConfig := oauth2.Config{
		ClientID:     authConfig.OIDC.ClientID,
		ClientSecret: authConfig.OIDC.ClientSecret.GetValue(),
		RedirectURL:  redirectURL,
		Scopes:       authConfig.OIDC.NormalizedScopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
	authURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallengeS256(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	ctx.Redirect(authURL, fasthttp.StatusFound)
}

func (h *SessionHandler) completeOIDCLogin(ctx *fasthttp.RequestCtx) {
	authConfig, err := h.getEnabledOIDCAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusForbidden, err.Error())
		return
	}
	errorParam := string(ctx.QueryArgs().Peek("error"))
	if errorParam != "" {
		SendError(ctx, fasthttp.StatusUnauthorized, fmt.Sprintf("OIDC login failed: %s", errorParam))
		return
	}
	code := string(ctx.QueryArgs().Peek("code"))
	state := string(ctx.QueryArgs().Peek("state"))
	if code == "" || state == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "OIDC callback is missing code or state")
		return
	}
	pendingCookie := string(ctx.Request.Header.Cookie(oidcLoginCookieName))
	pending, err := openOIDCLoginCookie(pendingCookie, authConfig.OIDC.ClientSecret.GetValue())
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "OIDC login state is invalid or expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		SendError(ctx, fasthttp.StatusUnauthorized, "OIDC login state mismatch")
		return
	}
	discovery, _, err := discoverOIDC(ctx, authConfig.OIDC.IssuerURL)
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Failed to discover OIDC provider: %v", err))
		return
	}
	token, err := exchangeOIDCCode(ctx, authConfig.OIDC, discovery, code, pending.CodeVerifier, oidcRedirectURL(ctx, authConfig.OIDC))
	if err != nil {
		SendError(ctx, fasthttp.StatusBadGateway, fmt.Sprintf("Failed to exchange OIDC code: %v", err))
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		SendError(ctx, fasthttp.StatusBadGateway, "OIDC provider did not return an ID token")
		return
	}
	claims, err := verifyOIDCIDToken(ctx, rawIDToken, discovery, authConfig.OIDC.ClientID, pending.Nonce)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, fmt.Sprintf("OIDC ID token validation failed: %v", err))
		return
	}
	if !isOIDCEmailAllowed(claims.Email, authConfig.OIDC) {
		SendError(ctx, fasthttp.StatusForbidden, "OIDC user is not allowed to access this dashboard")
		return
	}
	sessionToken, expiresAt, err := h.createDashboardSession(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
		return
	}
	clearOIDCLoginCookie(ctx)
	setDashboardSessionCookie(ctx, sessionToken, expiresAt)
	ctx.Response.Header.Set("Location", pending.Goto)
	ctx.SetStatusCode(fasthttp.StatusFound)
}

func (h *SessionHandler) getEnabledOIDCAuthConfig(ctx context.Context) (*configstore.AuthConfig, error) {
	if h.configStore == nil {
		return nil, errors.New("authentication is not enabled")
	}
	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth config: %w", err)
	}
	if authConfig == nil || !authConfig.IsEnabled || authConfig.EffectiveAuthType() != configstore.AuthTypeOIDC {
		return nil, errors.New("OIDC authentication is not enabled")
	}
	if authConfig.OIDC == nil || !authConfig.OIDC.IsConfigured() {
		return nil, errors.New("OIDC authentication is not configured")
	}
	return authConfig, nil
}

func discoverOIDC(ctx context.Context, issuerURL string) (*oidcDiscoveryDocument, string, error) {
	issuer, err := normalizeIssuerURL(issuerURL)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	var discovery oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(discovery.AuthorizationEndpoint) == "" ||
		strings.TrimSpace(discovery.TokenEndpoint) == "" ||
		strings.TrimSpace(discovery.JWKSURI) == "" {
		return nil, "", errors.New("OIDC discovery document is missing required endpoints")
	}
	documentIssuer := strings.TrimRight(strings.TrimSpace(discovery.Issuer), "/")
	if documentIssuer != "" && documentIssuer != issuer {
		return nil, "", fmt.Errorf("OIDC issuer mismatch: expected %q, got %q", issuer, documentIssuer)
	}
	if documentIssuer == "" {
		discovery.Issuer = issuer
	}
	return &discovery, issuer, nil
}

func exchangeOIDCCode(ctx context.Context, oidcConfig *configstore.OIDCAuthConfig, discovery *oidcDiscoveryDocument, code string, verifier string, redirectURL string) (*oauth2.Token, error) {
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, oidcHTTPClient)
	oauthConfig := oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret.GetValue(),
		RedirectURL:  redirectURL,
		Scopes:       oidcConfig.NormalizedScopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}
	return oauthConfig.Exchange(exchangeCtx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
}

func verifyOIDCIDToken(ctx context.Context, rawToken string, discovery *oidcDiscoveryDocument, clientID string, nonce string) (*oidcClaims, error) {
	keySet, err := fetchOIDCJWKS(ctx, discovery.JWKSURI)
	if err != nil {
		return nil, err
	}
	claims := &oidcClaims{}
	parser := jwt.NewParser(
		jwt.WithIssuer(discovery.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	token, err := parser.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unsupported ID token signing method %q", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("ID token is missing kid")
		}
		key, ok := keySet[kid]
		if !ok {
			return nil, fmt.Errorf("no matching JWKS key for kid %q", kid)
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, errors.New("ID token is invalid")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	return claims, nil
}

func fetchOIDCJWKS(ctx context.Context, jwksURI string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Kid == "" || key.N == "" || key.E == "" {
			continue
		}
		publicKey, err := rsaPublicKeyFromJWK(key.N, key.E)
		if err != nil {
			continue
		}
		keys[key.Kid] = publicKey
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS endpoint returned no usable RSA keys")
	}
	return keys, nil
}

func rsaPublicKeyFromJWK(n string, e string) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}
	exponent := new(big.Int).SetBytes(exponentBytes).Int64()
	if exponent <= 0 || exponent > int64(^uint(0)>>1) {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent),
	}, nil
}

func sealOIDCLoginCookie(pending oidcLoginCookie, secret string) (string, error) {
	payload, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encodedPayload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encodedPayload + "." + signature, nil
}

func openOIDCLoginCookie(value string, secret string) (oidcLoginCookie, error) {
	var pending oidcLoginCookie
	if value == "" {
		return pending, errors.New("missing OIDC login cookie")
	}
	encodedPayload, encodedSignature, ok := strings.Cut(value, ".")
	if !ok || encodedPayload == "" || encodedSignature == "" {
		return pending, errors.New("malformed OIDC login cookie")
	}
	expectedMAC := hmac.New(sha256.New, []byte(secret))
	expectedMAC.Write([]byte(encodedPayload))
	expectedSignature := base64.RawURLEncoding.EncodeToString(expectedMAC.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(encodedSignature), []byte(expectedSignature)) != 1 {
		return pending, errors.New("OIDC login cookie signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return pending, err
	}
	if err := json.Unmarshal(payload, &pending); err != nil {
		return pending, err
	}
	if pending.ExpiresAt <= time.Now().Unix() {
		return pending, errors.New("OIDC login cookie expired")
	}
	if pending.State == "" || pending.Nonce == "" || pending.CodeVerifier == "" {
		return pending, errors.New("OIDC login cookie is incomplete")
	}
	pending.Goto = safeDashboardGoto(pending.Goto)
	return pending, nil
}

func setOIDCLoginCookie(ctx *fasthttp.RequestCtx, value string, expiresAt time.Time) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey(oidcLoginCookieName)
	cookie.SetValue(value)
	cookie.SetExpire(expiresAt)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	cookie.SetSecure(isHTTPSRequest(ctx))
	ctx.Response.Header.SetCookie(cookie)
}

func clearOIDCLoginCookie(ctx *fasthttp.RequestCtx) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey(oidcLoginCookieName)
	cookie.SetValue("")
	cookie.SetExpire(time.Now().Add(-dashboardSessionTTL))
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	cookie.SetSecure(isHTTPSRequest(ctx))
	ctx.Response.Header.SetCookie(cookie)
}

func randomURLSafe(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func normalizeIssuerURL(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", errors.New("issuer_url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("issuer_url must be absolute")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", errors.New("issuer_url must use http or https")
	}
	return trimmed, nil
}

func oidcRedirectURL(ctx *fasthttp.RequestCtx, oidcConfig *configstore.OIDCAuthConfig) string {
	if oidcConfig != nil && strings.TrimSpace(oidcConfig.RedirectURL) != "" {
		return strings.TrimSpace(oidcConfig.RedirectURL)
	}
	proto := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-Proto")))
	if proto != "https" && proto != "http" {
		if isHTTPSRequest(ctx) {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-Host")))
	if host == "" {
		host = string(ctx.Host())
	}
	return proto + "://" + host + "/api/session/sso/callback"
}

func safeDashboardGoto(raw string) string {
	const fallback = "/workspace"
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	if strings.HasPrefix(trimmed, "//") ||
		strings.Contains(trimmed, "\\") ||
		strings.ContainsAny(trimmed, "\r\n") {
		return fallback
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.IsAbs() || !strings.HasPrefix(parsed.Path, "/") {
		return fallback
	}
	if !isAllowedDashboardGoto(trimmed) {
		return fallback
	}
	return trimmed
}

func isAllowedDashboardGoto(value string) bool {
	return value == "/workspace" ||
		strings.HasPrefix(value, "/workspace/") ||
		strings.HasPrefix(value, "/workspace?") ||
		strings.HasPrefix(value, "/workspace#") ||
		value == "/oauth/consent" ||
		strings.HasPrefix(value, "/oauth/consent/") ||
		strings.HasPrefix(value, "/oauth/consent?") ||
		strings.HasPrefix(value, "/oauth/consent#")
}

func isOIDCEmailAllowed(email string, oidcConfig *configstore.OIDCAuthConfig) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	hasAllowlist := oidcConfig != nil && (len(oidcConfig.AllowedEmails) > 0 || len(oidcConfig.AllowedEmailDomains) > 0)
	if !hasAllowlist {
		return true
	}
	for _, allowedEmail := range oidcConfig.AllowedEmails {
		if strings.EqualFold(strings.TrimSpace(allowedEmail), email) {
			return true
		}
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok || domain == "" {
		return false
	}
	for _, allowedDomain := range oidcConfig.AllowedEmailDomains {
		if strings.EqualFold(strings.TrimSpace(allowedDomain), domain) {
			return true
		}
	}
	return false
}
