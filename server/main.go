package main

import (
	"path/filepath"
	"server/api"
	"server/azure"
	"server/config"
	"server/controllers"
	"server/engine"
	"server/handler"
	"server/model"
	"server/persistence"

	log "github.com/sirupsen/logrus"
)

func main() {
	config.ConfigureLogging()
	config.ParseArgs()

	db := persistence.NewPersistentDB(filepath.Join(config.GetEnvironment().BASE_PATH, config.GetEnvironment().DB_REL_PATH))
	// TODO store first start up in DB so we can determine max allowed run time for installer

	// Instantiate Azure clients and session
	azure.EnsureAzureLogin(nil)
	deploymentsClient := azure.NewDeploymentsClient(nil)

	// Graceful exit handler
	exit := controllers.NewExitController()

	var loginManager handler.LoginManager
	// Fallback in case SSO setup fails
	loginManager = handler.CredentialsHandler{}

	// TODO move all this outside main!
	// If SSO, create SSO manager
	if config.GetEnvironment().AUTH_TYPE == "SSO" {
		ssoManager := handler.NewSsoManager(exit.Context())
		store := model.GetSsoStore()
		// TODO, maybe spin this off and retry until it works
		// For now if we can't create client, do normal login
		var credentials *model.SsoCredentials
		var err error
		if store == nil {
			// Create dynamic client, get credentials
			credentials, err = getSsoClientCredentials(ssoManager, db)
			if err != nil {
				log.Errorf("Unable to create client and get credentials: %v", err)
			}
		} else {
			// Fetch from db
			credentials, err = model.GetSsoStore().GetSsoClientCredentials()
			if err != nil {
				log.Errorf("Unable to load credentials from db: %v", err)
			}
		}
		// Create authenticator, must be done after SSO client and credentials are in db
		if credentials != nil {
			err := ssoManager.AddAuthenticator(credentials.ClientId, credentials.ClientSecret)
			if err != nil {
				log.Errorf("Unable to create SSO authenticator, fall back to credentials login: %v", err)
			} else {
				loginManager = ssoManager.SsoHandler
				// TODO probably move deletion to engine shutdown.
				defer ssoManager.AcsClient.DeleteACSClient(credentials.ClientId)
			}
		}
	}

	engine := engine.NewEngine(exit.Context(), db, deploymentsClient)

	app := api.NewApp(db, engine, loginManager)

	// Start listening for shutdown signal
	exit.Start()

	// Start the engine
	go engine.Run()

	// Start the API server
	go app.Run()

	// Wait for either the engine being done or a signal received by exit controller
	select {
	case <-exit.Done():
	case <-engine.Done():
	}
}

func getSsoClientCredentials(ssoManager *handler.SsoManager, db *persistence.Database) (*model.SsoCredentials, error) {
	credentials, err := ssoManager.AcsClient.GetClientCredentials(handler.GetRedirectUrl())
	if err != nil {
		log.Errorf("Unable to create SSO client, fall back to credentials login: %v", err)
		return nil, err
	} else {
		model.InitSsoStore(db.Instance).SetSsoClientCredentials(credentials.ClientId, credentials.ClientSecret)
	}
	return credentials, nil
}
