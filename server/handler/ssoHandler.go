package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"server/config"
	"server/model"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SsoHandler struct {
	Auth *Authenticator
}

func (a SsoHandler) GetLoginHandler() HandleFuncWithDB {

	return func(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
		state, err := generateRandomState()
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		log.Infof("BRY: Auth code URL: %s", a.Auth.Config.AuthCodeURL(state))
		// Redirect to SSO
		http.Redirect(w, r, a.Auth.Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
	}
}

func (a SsoHandler) SsoRedirect(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	session_state := r.URL.Query().Get("session_state")
	log.Printf("Returned code %s, state %s, and session_state %s", code, state, session_state)

	oauth2Token, err := a.Auth.Config.Exchange(context.Background(), code)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("<body>Err when exchanging: %v", err)))
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	log.Printf("Oauth2 token: %v", oauth2Token)
	ssoCredentials := &model.SsoCredentials{}
	if err := db.Find(ssoCredentials).Error; err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	idToken, err := a.Auth.VerifyToken(oauth2Token, ssoCredentials.ClientId)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
	}
	log.Printf("ID token: %v", idToken)
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

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}
