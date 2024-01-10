package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/sync/errgroup"
)

func main() {

	// Configure your TSM here
	credsBytes, err := os.ReadFile("./credentials/user.json")
	if err != nil {
		panic(err)
	}
	var creds tsm.PasswordCredentials
	if err := creds.UnmarshalJSON(credsBytes); err != nil {
		panic(err)
	}
	// Create clients for each player

	playerCount := len(creds.URLs)
	ecdsaClients := make([]tsm.ECDSAClient, playerCount)
	for player := 0; player < playerCount; player++ {
		credsPlayer := tsm.PasswordCredentials{
			UserID:    creds.UserID,
			URLs:      []string{creds.URLs[player]},
			Passwords: []string{creds.Passwords[player]},
		}
		client, err := tsm.NewPasswordClientFromCredentials(3, 1, credsPlayer)
		if err != nil {
			log.Fatal(err)
		}
		ecdsaClients[player] = tsm.NewECDSAClient(client)
	}

	// Generate an ECDSA key

	sessionID := tsm.GenerateSessionID()

	var eg errgroup.Group
	fmt.Println("Enter key id")
	keyIDPrompt := promptui.Prompt{
		Label: "Key ID",
	}

	keyID, err := keyIDPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}

	// Create an ERS key pair and ERS label
	// Here we generate the private key in the clear, but it could also be exported from an HSM

	ersPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	ersPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(ersPrivateKey)

	ersPublicKey, err := x509.MarshalPKIXPublicKey(&ersPrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	ersLabel := []byte("test")

	// Collect the partial recovery data

	sessionID = tsm.GenerateSessionID()
	var partialRecoveryData = make([][]byte, len(ecdsaClients))
	for i := range ecdsaClients {
		i := i
		eg.Go(func() error {
			var err error
			r, err := ecdsaClients[i].PartialRecoveryInfo(sessionID, keyID, ersPublicKey, ersLabel)
			partialRecoveryData[i] = r[0]
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}

	// Combine the partial recovery data

	recoveryData, err := tsm.RecoveryInfoCombine(partialRecoveryData, ersPublicKey, ersLabel)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the combined recovery data against the ERS public key and the public ECDSA key

	publicKey, err := ecdsaClients[0].PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = tsm.RecoveryInfoValidate(recoveryData, ersPublicKey, ersLabel, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Recover the private ECDSA key

	curveName, privateECDSAKey, masterChainCode, err := tsm.RecoverKeyECDSA(recoveryData, ersPrivateKeyBytes, ersLabel)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Curve:                      ", curveName)
	fmt.Println("recovered private ECDSA key:", privateECDSAKey)
	fmt.Println("Recovered master chain code:", hex.EncodeToString(masterChainCode))

	// Convert D value to hexadecimal string
	privateKeyHex := fmt.Sprintf("%x", privateECDSAKey.D)

	// Print the private key as a hexadecimal string
	fmt.Printf("Private Key: %s\n", privateKeyHex)
}
