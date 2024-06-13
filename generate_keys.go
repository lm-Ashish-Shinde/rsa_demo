package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func generateKeyPair(dir string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey

	// Save private key to file
	privateKeyFile := fmt.Sprintf("%s/private.pem", dir)
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateKeyPEMFile, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer privateKeyPEMFile.Close()
	if err := pem.Encode(privateKeyPEMFile, privateKeyPEM); err != nil {
		return err
	}

	// Save public key to file
	publicKeyFile := fmt.Sprintf("%s/public.pem", dir)
	publicKeyPEM := &pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}
	publicKeyPEMFile, err := os.Create(publicKeyFile)
	if err != nil {
		return err
	}
	defer publicKeyPEMFile.Close()
	if err := pem.Encode(publicKeyPEMFile, publicKeyPEM); err != nil {
		return err
	}

	return nil
}

func main() {
	dir := "./keys" // Directory to save keys

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// Generate Key Pair and Save to Files
	if err := generateKeyPair(dir); err != nil {
		fmt.Println("Error generating and saving key pair:", err)
		return
	}
	fmt.Println("Key pair generated and saved successfully.")
}
