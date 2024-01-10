package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/sha3"
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

	chainPath := []uint32{1, 2, 3, 4}
	derPublicKey, err := ecdsaClients[0].PublicKey(keyID, chainPath)
	if err != nil {
		panic(err)
	}

	publicKey, err := ecdsaClients[0].ParsePublicKey(derPublicKey)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 2*32)
	publicKey.X.FillBytes(msg[0:32])
	publicKey.Y.FillBytes(msg[32:64])

	h := sha3.NewLegacyKeccak256()
	_, err = h.Write(msg)
	if err != nil {
		panic(err)
	}
	hashValue := h.Sum(nil)

	// Ethereum address is rightmost 160 bits of the hash value
	ethAddress := hex.EncodeToString(hashValue[len(hashValue)-20:])
	fmt.Println("Ethereum address: ", ethAddress)
}
