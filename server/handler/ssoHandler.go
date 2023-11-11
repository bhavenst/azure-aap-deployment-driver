package handler

import (
	"context"
	"fmt"
	"net/http"
	"server/config"
	"server/model"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SsoHandler struct {
	Auth  *Authenticator
	State string
}

func (a *SsoHandler) GetLoginHandler() HandleFuncWithDB {
	return func(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
		// Redirect to SSO
		http.Redirect(w, r, a.Auth.Config.AuthCodeURL(a.State), http.StatusTemporaryRedirect)
	}
}

func (a *SsoHandler) SsoRedirect(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if state != a.State {
		respondError(w, http.StatusUnauthorized, "SSO state values do not match.")
	}
	// TODO Seems this is needed only for later verifying the SSO session,
	// for instance to ensure the user has not logged out.  Not sure we need it.
	_ = r.URL.Query().Get("session_state")

	oauth2Token, err := a.Auth.Config.Exchange(context.Background(), code)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	// Load SSO client credentials from db
	ssoCredentials := &model.SsoCredentials{}
	if err := db.Find(ssoCredentials).Error; err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	idToken, err := a.Auth.VerifyToken(oauth2Token, ssoCredentials.ClientId)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	if idToken != nil {
		log.Infof("Logged in: %v", idToken.Subject)
	} else {
		log.Info("Someone logged in, id token is null")
	}
	sessionHelper, err := getSessionHelper()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	sessionHelper.SetupSession(r, w)
	http.Redirect(w, r, fmt.Sprintf("https://%s", config.GetEnvironment().INSTALLER_DOMAIN_NAME), http.StatusTemporaryRedirect)
}
