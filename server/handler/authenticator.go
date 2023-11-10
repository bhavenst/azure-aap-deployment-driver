package handler

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authenticator struct {
	Config   oauth2.Config
	provider *oidc.Provider
	ctx      context.Context
}

func NewAuthenticator(ctx context.Context, ssoEndpoint string, redirectUrl string, clientId string, clientSecret string) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, ssoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to instantiate new OIDC provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		// Client ID fro CIAM team
		ClientID: clientId,
		// Secret from CIAM team, would come from keyvault
		ClientSecret: clientSecret,
		// The base URL here is registered with the CIAM/SSO instance.  It is possible to add routes to the end of the query,
		// but the base URL must match.  For instance, /callback could be added.
		RedirectURL: redirectUrl,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		// sub (subject), email, email_verified, organization.id are also required/automatic according to:
		// https://source.redhat.com/groups/public/ciams/docs/external_sso_ssoredhatcom_claims__attributes
		Scopes: []string{oidc.ScopeOpenID},
	}
	return &Authenticator{
		Config:   oauth2Config,
		provider: provider,
		ctx:      ctx,
	}, nil
}

func (a *Authenticator) VerifyToken(token *oauth2.Token, clientId string) (*oidc.IDToken, error) {
	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("failed to Id token from oauth2 token")
	}

	// Verify the token
	verifier := a.provider.Verifier(&oidc.Config{ClientID: clientId})
	idToken, err := verifier.Verify(a.ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %v", err)
	}
	return idToken, err
}
