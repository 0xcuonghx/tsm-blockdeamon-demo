package main

import (
	"fmt"
	"os"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/sync/errgroup"
)

func main() {

	const (
		playerCount = 3 // Number of MPC nodes in the TSM
		threshold   = 1 // The security threshold
	)

	credsBytes, err := os.ReadFile("./credentials/user.json")
	if err != nil {
		panic(err)
	}
	var creds tsm.PasswordCredentials
	if err := creds.UnmarshalJSON(credsBytes); err != nil {
		panic(err)
	}

	// Create individual clients for each MPC node

	ecdsaClients := make([]tsm.ECDSAClient, playerCount)
	for player := 0; player < playerCount; player++ {
		credsPlayer := tsm.PasswordCredentials{
			UserID:    creds.UserID,
			URLs:      []string{creds.URLs[player]},
			Passwords: []string{creds.Passwords[player]},
		}
		client, err := tsm.NewPasswordClientFromCredentials(playerCount, threshold, credsPlayer)
		if err != nil {
			panic(err)
		}
		ecdsaClients[player] = tsm.NewECDSAClient(client)
	}

	// Generate ECSDA key

	keyGenSessionID := tsm.GenerateSessionID()
	var keyID string
	var eg errgroup.Group
	for i := 0; i < playerCount; i++ {
		i := i
		eg.Go(func() error {
			var err error
			keyID, err = ecdsaClients[i].KeygenWithSessionID(keyGenSessionID, "secp256k1")
			return err
		})
	}
	if err = eg.Wait(); err != nil {
		panic(err)
	}
	fmt.Println("Generated key with ID:", keyID)

}
