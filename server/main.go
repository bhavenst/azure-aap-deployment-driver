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
	// If SSO, create SSO manager
	if config.GetEnvironment().AUTH_TYPE == "SSO" {
		ssoMan := handler.NewSsoManager(exit.Context())
		clientId, clientSecret := ssoMan.AcsClient.GetClientCredentials(handler.GetRedirectUrl())
		model.InitSsoStore(db.Instance).SetSsoClientCredentials(clientId, clientSecret)
		ssoMan.AddAuthenticator()
		loginManager = ssoMan.SsoHandler
		defer ssoMan.AcsClient.DeleteACSClient(clientId) // TODO probably move to engine shutdown to avoid doing it too early
	} else {
		loginManager = handler.CredentialsHandler{}
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
