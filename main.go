package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
)

func main() {
	ciphertext, err := Encrypt([]byte("sekret"), []byte("some secret text"))
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	fmt.Println("Encrypted: " + string(ciphertext))

	plaintext, err := Decrypt([]byte("sekret"), ciphertext)
	if err != nil {
		fmt.Printf("Error decrypting: %v\n", err)
		return
	}

	fmt.Println("Decrypted: " + string(plaintext))
}

func Encrypt(password, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 8)
	rand.Read(salt)

	key, err := HashPassword(password, salt)
	if err != nil {
		return nil, fmt.Errorf("Error hashing password: %w", err)
	}

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	// This encrypts "hello world" and appends the result to the nonce.
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, key)

	result := append(salt, encrypted[:]...)

	return []byte(base64.StdEncoding.EncodeToString(result)), nil
}

func Decrypt(password, ciphertext []byte) ([]byte, error) {
	rawCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	key, err := HashPassword(password, rawCiphertext[:8])
	if err != nil {
		return nil, fmt.Errorf("Error hashing password: %w", err)
	}

	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. The nonce is stored in byte 8-32
	// 24 bytes of the encrypted text.
	var nonce [24]byte
	copy(nonce[:], rawCiphertext[8:32])

	decrypted, ok := secretbox.Open(nil, rawCiphertext[32:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("Decryption error")
	}

	return decrypted, nil
}

// HashPassword takes a password and converts it to a 32 byte length key
// that can be used for encrypting.
func HashPassword(password, salt []byte) (*[32]byte, error) {
	k, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("Error hashing password: %w", err)
	}
	var key [32]byte
	copy(key[:], k)
	return &key, nil
}
