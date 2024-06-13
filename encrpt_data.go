package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func encrypt(plainText []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		plainText,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func main() {
	// Read public key from file
	publicKeyFile, err := os.Open("./public.pem")
	if err != nil {
		fmt.Println("Error opening public key file:", err)
		return
	}
	defer publicKeyFile.Close()

	// Decode the PEM block to get the public key
	info, err := publicKeyFile.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	keyBytes := make([]byte, info.Size())
	_, err = publicKeyFile.Read(keyBytes)
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		fmt.Println("Invalid PEM block")
		return
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Encrypt
	originalMessage := []byte("This is the super secret message, that should be keep hidden.")
	ciphertext, err := encrypt(originalMessage, publicKey)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("Encrypted Message:", encodedCiphertext)
}
