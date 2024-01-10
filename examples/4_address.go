package main

import (
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
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

	// Get the public key
	pkDER, err := ecdsaClients[0].PublicKey(keyID, nil)
	if err != nil {
		// handle error
	}
	pk, err := ASN1ParseSecp256k1PublicKey(pkDER)
	if err != nil {
		// handle error
	}
	address := crypto.PubkeyToAddress(*pk)

	fmt.Println("Ethereum address: ", address)

}

func ASN1ParseSecp256k1PublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	publicKeyInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}

	postfix, err := asn1.Unmarshal(publicKey, &publicKeyInfo)
	if err != nil || len(postfix) > 0 {
		return nil, errors.New("invalid or incomplete ASN1")
	}
	// check params

	pk, err := secp.ParsePubKey(publicKeyInfo.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	return pk.ToECDSA(), nil
}
