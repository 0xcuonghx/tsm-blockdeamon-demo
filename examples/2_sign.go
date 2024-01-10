package main

import (
	"crypto/sha256"
	"encoding/hex"
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

	// Generate partial signatures using the key

	message := []byte("This is the message to be signed")
	msgHash := sha256.Sum256(message)
	chainPath := []uint32{2, 5} // Sign using the derived key m/2/5

	players := []int{0, 2} // Choose a subset of threshold+1 players to participate in signature generation
	partialSignatures := make([][]byte, len(players))

	// The call to PartialSign is blocking, so we must call each ecdsaClient concurrently.
	signSessionID := ecdsaClients[0].GenerateSessionID()
	fmt.Println("Generating signature using players", players)
	for i, player := range players {
		i, player := i, player
		eg.Go(func() error {
			var err error
			partialSignatures[i], err = ecdsaClients[player].PartialSign(signSessionID, keyID, chainPath, msgHash[:], players...)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		panic(err)
	}

	// Combine the partial signatures into an actual signature

	signature, _, err := tsm.ECDSAFinalize(partialSignatures...)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(signature))
}
