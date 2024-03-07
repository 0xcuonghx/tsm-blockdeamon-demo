package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/sync/errgroup"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	var (
		rpcEndpoint = os.Getenv("RPC_ENDPOINT")
	)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		log.Fatal(err)
	}

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

	// Create a transaction
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Enter send amount")
	amountPrompt := promptui.Prompt{
		Label: "Amount",
	}

	amount, err := amountPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	value := new(big.Int)
	value.SetString(amount, 10)
	gasLimit := uint64(21000) // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	toAddress := common.HexToAddress("0xBac8ECdbc45A50d3bda7246bB2AA64Fc449C7924")
	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("chainID: %s\n", chainID)

	signer := types.NewEIP155Signer(chainID)
	fmt.Println("sign tx")

	h := signer.Hash(tx)

	players := []int{0, 2} // Choose a subset of threshold+1 players to participate in signature generation
	partialSignatures := make([][]byte, len(players))

	// The call to PartialSign is blocking, so we must call each ecdsaClient concurrently.
	signSessionID := ecdsaClients[0].GenerateSessionID()
	fmt.Println("Generating signature using players", players)
	for i, player := range players {
		i, player := i, player
		eg.Go(func() error {
			var err error
			partialSignatures[i], err = ecdsaClients[player].PartialSign(signSessionID, keyID, nil, h[:], players...)
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		panic(err)
	}

	// Combine the partial signatures into an actual signature

	signatureDER, recoveryID, err := tsm.ECDSAFinalize(partialSignatures...)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(signatureDER))
	r, s, err := ASN1ParseSecp256k1Signature(signatureDER)
	if err != nil {
		log.Fatal(err)
	}
	signature := make([]byte, 2*32+1)
	r.FillBytes(signature[0:32])
	s.FillBytes(signature[32:64])
	signature[64] = byte(recoveryID)

	// add signature to transaction
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("send tx")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())
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

func ASN1ParseSecp256k1Signature(signature []byte) (r, s *big.Int, err error) {
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	postfix, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}
	if len(postfix) > 0 {
		return nil, nil, errors.New("trailing bytes for ASN1 ecdsa signature")
	}
	return sig.R, sig.S, nil
}
