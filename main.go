package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

func securePrompt(prompt string) (string, error) {
	fmt.Printf("%s:", prompt)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("Error in secure prompt: %s", err)
	}

	return string(bytepw), nil
}

type entry struct {
	Notes  string `json:"description"`
	Secret string `json:"secret"`
}

type pwsFile struct {
	Entries map[string]entry `json:"entries"`
}

func openPWSFile(pwsFilePath string) (p pwsFile, e error) {
	f, err := ioutil.ReadFile(pwsFilePath)
	if err != nil {
		return p, fmt.Errorf("error reading file at %s: %s", pwsFilePath, err)
	}

	err = json.Unmarshal(f, &p)
	if err != nil {
		return p, fmt.Errorf("error unmarshaling file: %s", err)
	}

	return p, nil
}

func main() {
	switch command := os.Args[1]; command {
	case "get":
		key := os.Args[2]

		pwsFile, err := openPWSFile(".pws.test.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening pws file: %s\n", err)
			os.Exit(1)
		}

		entry, found := pwsFile.Entries[key]
		if !found {
			fmt.Println("%s not found", key)
			return
		}

		fmt.Println(entry.Notes)

		pass, err := securePrompt("Enter password to decrypt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error prompting for password: %s\n", err)
			os.Exit(1)
		}

		decryptedSecret, err := Decrypt(entry.Secret, pass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting secret: %s\n", err)
			os.Exit(1)
		}

		fmt.Println(decryptedSecret)

	case "set":
		key := os.Args[2]

		pwsFile, err := openPWSFile(".pws.test.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening pws file: %s\n", err)
			os.Exit(1)
		}

		secret, err := securePrompt("Enter secret to store")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error entering password: %s\n", err)
			os.Exit(1)
		}

		pass, err := securePrompt("Enter encryption password")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error prompting for password: %s\n", err)
			os.Exit(1)
		}

		confirmPass, err := securePrompt("Confirm encryption password")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error prompting for password: %s\n", err)
			os.Exit(1)
		}

		if pass != confirmPass {
			fmt.Fprintf(os.Stderr, "Passwords do not match!\n")
			os.Exit(1)
		}

		ciphertext, err := Encrypt(pass, secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting secret: %s\n", err)
			os.Exit(1)
		}

		pwsFile.Entries[key].Secret = ciphertext

		err = SaveFile(pwsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %s\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Invalid option: %s\n", os.Args)
		os.Exit(1)
	}
}

func SaveFile(f pwsFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling file: %s", err)
	}

	err = ioutil.WriteFile(".pws.test.json", data, 0644)
	if err != nil {
		fmt.Printf("error writing out file: %s", err)
	}

	return nil
}

func Encrypt(password, plaintext string) (string, error) {
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("error generating salt: %s", err)
	}

	key, err := HashPassword([]byte(password), salt)
	if err != nil {
		return "", fmt.Errorf("error hashing password: %s", err)
	}

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}

	// This encrypts "hello world" and appends the result to the nonce.
	encrypted := secretbox.Seal(nonce[:], []byte(plaintext), &nonce, key)

	result := append(salt, encrypted[:]...)

	return base64.StdEncoding.EncodeToString(result), nil
}

func Decrypt(ciphertext, password string) (string, error) {
	rawCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %s", err)
	}

	key, err := HashPassword([]byte(password), rawCiphertext[:8])
	if err != nil {
		return "", fmt.Errorf("error hashing password: %s", err)
	}

	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. The nonce is stored in byte 8-32
	// 24 bytes of the encrypted text.
	var nonce [24]byte
	copy(nonce[:], rawCiphertext[8:32])

	decrypted, ok := secretbox.Open(nil, rawCiphertext[32:], &nonce, key)
	if !ok {
		return "", fmt.Errorf("decryption error")
	}

	return string(decrypted), nil
}

// HashPassword takes a password and converts it to a 32 byte length key
// that can be used for encrypting.
func HashPassword(password, salt []byte) (*[32]byte, error) {
	k, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %s", err)
	}
	var key [32]byte
	copy(key[:], k)
	return &key, nil
}
