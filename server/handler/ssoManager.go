package handler

import (
	"context"
	"server/config"
	"server/model"
	"server/sso"

	log "github.com/sirupsen/logrus"
)

type SsoManager struct {
	Context       context.Context
	Authenticator *Authenticator
	AcsClient     *sso.AcsClient
	SsoHandler    *SsoHandler
}

func NewSsoManager(ctx context.Context) *SsoManager {
	client := sso.NewAcsClient(ctx)
	return &SsoManager{
		Context:   ctx,
		AcsClient: client,
	}
}

func (s *SsoManager) AddAuthenticator() error {
	creds, err := model.GetSsoStore().GetSsoClientCredentials()
	if err != nil {
		log.Errorf("unable to load client credentials from db: %v", err)
	}
	auth, err := NewAuthenticator(s.Context, config.GetEnvironment().SSO_ENDPOINT, GetRedirectUrl(), creds.ClientId, creds.ClientSecret)
	if err != nil {
		log.Fatalf("Unable to instantiate SSO authenticator: %v", err)
	}
	s.SsoHandler = &SsoHandler{Auth: auth}
	return nil
}
