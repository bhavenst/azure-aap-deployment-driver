package model

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SsoStore interface {
	SetSsoClientCredentials(string, string) error
	GetSsoClientCredentials() (*SsoCredentials, error)
}

var once sync.Once
var Store SsoStore

type SsoCredentials struct {
	ClientId     string
	ClientSecret string
}

type ssoStore struct {
	db *gorm.DB
}

func InitSsoStore(db *gorm.DB) SsoStore {
	once.Do(func() {
		Store = ssoStore{
			db: db,
		}
	})
	return Store
}

func GetSsoStore() SsoStore {
	if Store == nil {
		log.Error("Sso Store not yet initialized.")
		return nil
	}
	return Store
}

func (s ssoStore) SetSsoClientCredentials(clientId string, clientSecret string) error {
	creds := &SsoCredentials{}
	err := s.db.Where(SsoCredentials{ClientId: clientId}).Assign(SsoCredentials{ClientSecret: clientSecret}).FirstOrCreate(creds).Error
	if err != nil {
		return fmt.Errorf("unable to store/update SSO credentials in DB: %v", err)
	}
	return nil
}

func (s ssoStore) GetSsoClientCredentials() (*SsoCredentials, error) {
	creds := &SsoCredentials{}
	if err := s.db.First(creds).Error; err != nil {
		return nil, fmt.Errorf("unable to load SSO credentials from DB: %v", err)
	}
	return creds, nil
}
