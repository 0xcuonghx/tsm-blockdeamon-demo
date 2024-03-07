package main

import (
	"fmt"
	"os"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func main() {

	// Log in as the initial admin, create a regular user, and save the user's credentials in 'user.json'.
	const (
		playerCount = 3 // Number of MPC nodes in the TSM
		threshold   = 1 // The security threshold
	)

	credsBytes, err := os.ReadFile("./credentials/admin.json")
	if err != nil {
		panic(err)
	}
	var creds tsm.PasswordCredentials
	if err := creds.UnmarshalJSON(credsBytes); err != nil {
		panic(err)
	}

	admClient, err := tsm.NewPasswordClientFromCredentials(3, 1, creds)
	if err != nil {
		panic(err)
	}
	var uc = tsm.NewUsersClient(admClient)
	userCreds, err := uc.CreatePasswordUser("user", "")
	if err != nil {
		panic(err)
	}
	fmt.Println("Created regular user with user ID", userCreds.UserID)
	userJson, err := userCreds.Encode()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("./credentials/user.json", []byte(userJson), 0666)
	if err != nil {
		panic(err)
	}
}
