package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"server/config"
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

func (s *SsoManager) AddAuthenticator(clientId string, clientSecret string) error {

	auth, err := NewAuthenticator(s.Context, config.GetEnvironment().SSO_ENDPOINT, GetRedirectUrl(), clientId, clientSecret)
	if err != nil {
		log.Errorf("unable to instantiate SSO authenticator: %v", err)
		return err
	}
	s.SsoHandler = &SsoHandler{Auth: auth, State: generateRandomState()}
	return nil
}

func generateRandomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)
	return state
}
