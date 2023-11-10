package handler

import (
	"fmt"
	"net/url"
	"server/config"

	log "github.com/sirupsen/logrus"
)

const REDIRECT_PATH string = "/callback"

func GetRedirectUrl() string {
	baseUrl := fmt.Sprintf("https://%s", config.GetEnvironment().INSTALLER_DOMAIN_NAME)
	_, err := url.JoinPath(baseUrl, REDIRECT_PATH)
	if err != nil {
		log.Fatalf("Unable to create SSO redirect URL: %v", err)
	}
	return baseUrl
}
