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

func decrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func main() {
	// Read private key from file
	privateKeyFile, err := os.Open("./private.pem")
	if err != nil {
		fmt.Println("Error opening private key file:", err)
		return
	}
	defer privateKeyFile.Close()

	// Decode the PEM block to get the private key
	info, err := privateKeyFile.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	keyBytes := make([]byte, info.Size())
	_, err = privateKeyFile.Read(keyBytes)
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Invalid PEM block")
		return
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	// Provide the base64 encoded encrypted message here
	// encodedCiphertext := "R8SC++YFBVi1Lh4tTQrxb6V/EpRnsP80D0nqdEAVUw9WE2+1GuqOumlhrjgS5GoOUkKD7IDxcUsq8zxUn6ANTvFqMowr5L5jNj5gFwO4wJJdm1EhWdVefWm7MqRIq/HQYx2USCjJNHiJz2hG7USsLsncx0oJ3DS+asCyXj9PWzSMzLaStuyz83GlFzAxCwfxjyAk5SJcECackUZ4e89toOCj8/zQmnKMuPr37/zDmJTLL/D0LS13Tom77KwObSI+r4EBFaslS8CYe9i4QwO8EVyFaEHi2FTyw4REHQUdVjPil+uVlvzUIb3CMBD/Rw/JcDLu+50wogzxwJWxPPwxPg=="
	fmt.Print("Enter the ciper text: ")
	var encodedCiphertext string
	textcp, err := fmt.Scan(&encodedCiphertext)
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}
	fmt.Println("Hello,", textcp)
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		fmt.Println("Error decoding ciphertext:", err)
		return
	}

	// Decrypt
	plaintext, err := decrypt(ciphertext, privateKey)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}
	fmt.Println("Decrypted Message:", string(plaintext))
}
