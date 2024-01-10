package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/sha3"
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

	//  ECSDA key

	fmt.Println("Enter key id")
	keyIDPrompt := promptui.Prompt{
		Label: "Key ID",
	}

	keyID, err := keyIDPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

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
