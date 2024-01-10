package main

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func main() {

	const (
		playerCount = 3 // Number of MPC nodes in the TSM
		threhsold   = 1 // Security threshold
	)

	// Create an admin client that connects to all MPC nodes

	servers := []string{"http://localhost:8500", "http://localhost:8501", "http://localhost:8502"}
	var nodes []tsm.Node
	for _, s := range servers {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		nodes = append(nodes, tsm.NewURLNode(*u, tsm.NullAuthenticator{}))
	}
	client := tsm.NewClient(playerCount, threhsold, nodes)
	ac := tsm.NewAdminClient(client)

	version, err := ac.TSMVersion()
	if err != nil {
		fmt.Println("Could not ping. Retrying...")
		time.Sleep(time.Second)
		version, err = ac.TSMVersion()
	}
	if err != nil {
		fmt.Println("Could not ping servers")
		panic(err)
	}
	fmt.Printf("TSM version: %s\n", version)

	// Use the admin client to create an initial admin user and save credentials to 'admin.json'.

	uc := tsm.NewUsersClient(client)
	adminCreds, err := uc.CreateInitialAdmin()
	if err != nil {
		fmt.Printf("Could not create initial admin: %s\n", err)
		fmt.Println("Exiting. We expect the TSM has already been initialized.")
		return
	}
	fmt.Println("Created initial admin with user ID", adminCreds.UserID)
	adminJson, err := adminCreds.Encode()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("./credentials/admin.json", []byte(adminJson), 0666)
	if err != nil {
		panic(err)
	}

	// Log in as the initial admin, create a regular user, and save the user's credentials in 'user.json'.

	admClient, err := tsm.NewPasswordClientFromCredentials(3, 1, adminCreds)
	if err != nil {
		panic(err)
	}
	uc = tsm.NewUsersClient(admClient)
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
