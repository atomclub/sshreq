package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/cli/browser"
	"github.com/cli/oauth/webapp"
)

// Initiate the OAuth App Authorization Flow for GitHub.com.
func requestLogin() (string, error) {
	flow, err := webapp.InitFlow()
	if err != nil {
		return "", err
	}

	params := webapp.BrowserParams{
		ClientID:    clientID,
		RedirectURI: callbackURL,
		Scopes:      []string{"user"},
		AllowSignup: false,
	}
	browserURL, err := flow.BrowserURL("https://github.com/login/oauth/authorize", params)
	if err != nil {
		return "", err
	}

	// A localhost server on a random available port will receive the web redirect.
	go func() {
		_ = flow.StartServer(nil)
	}()

	// Note: the user's web browser must run on the same device as the running app.
	err = browser.OpenURL(browserURL)
	if err != nil {
		return "", err
	}

	httpClient := http.DefaultClient
	accessToken, err := flow.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", webapp.WaitOptions{
		ClientSecret: clientSecret,
	})
	if err != nil {
		return "", err
	}

	slog.Debug("get access token", "token", accessToken.Token)
	// NOTE: Since we use Github Oauth App instead of Github App,
	// Token never expires.
	return accessToken.Token, nil
}
