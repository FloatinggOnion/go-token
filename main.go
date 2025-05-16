package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"
)

const (
	dataFile       = "totp_secrets.enc" // Encrypted datafile
	recoveryFile   = "recovery_key.enc" // Encrypted recovery key
	step           = 30
	digits         = 6
	recoveryKeyLen = 32 // Length of the recovery key
)

type Secrets map[string]string

// GenerateTOTP generates a TOTP code using the given secret.
func GenerateTOTP(secret string) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %v", err)
	}

	timeStep := time.Now().Unix() / step
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(timeStep))

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	code := (int32(hash[offset])&0x7F)<<24 |
		(int32(hash[offset+1])&0xFF)<<16 |
		(int32(hash[offset+2])&0xFF)<<8 |
		(int32(hash[offset+3]) & 0xFF)

	otp := int(code) % int(math.Pow10(digits))
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, otp), nil
}

// deriveKey derives a 32-byte AES key from a passphrase using SHA-256.
func deriveKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// encrypt encrypts data using AES-GCM.
func encrypt(data []byte, passphrase string) ([]byte, error) {
	key := deriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM.
func decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	key := deriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// generateRecoveryKey generates a random recovery key.
func generateRecoveryKey() ([]byte, error) {
	key := make([]byte, recoveryKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// setupRecovery encrypts and saves the recovery key.
func setupRecovery(masterPassword string) error {
	recoveryKey, err := generateRecoveryKey()
	if err != nil {
		return fmt.Errorf("failed to generate recovery key: %v", err)
	}

	encryptedRecoveryKey, err := encrypt(recoveryKey, masterPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt recovery key: %v", err)
	}

	if err := ioutil.WriteFile(recoveryFile, encryptedRecoveryKey, 0644); err != nil {
		return fmt.Errorf("failed to save recovery key: %v", err)
	}

	fmt.Println("Recovery key generated and saved. Keep it safe!")
	return nil
}

// recoverWithMasterPassword decrypts the recovery key using the master password.
func recoverWithMasterPassword(masterPassword string) ([]byte, error) {
	data, err := ioutil.ReadFile(recoveryFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery file: %v", err)
	}

	recoveryKey, err := decrypt(data, masterPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt recovery key: %v", err)
	}

	return recoveryKey, nil
}

// loadSecrets loads and decrypts the secrets from the encrypted datafile.
func loadSecrets(passphrase string) (Secrets, error) {
	data, err := ioutil.ReadFile(dataFile)
	if err != nil {
		return make(Secrets), nil // Return empty secrets if file doesn't exist
	}

	plaintext, err := decrypt(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt datafile: %v", err)
	}

	var secrets Secrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets: %v", err)
	}

	return secrets, nil
}

// saveSecrets encrypts and saves the secrets to the datafile.
func saveSecrets(secrets Secrets, passphrase string) error {
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %v", err)
	}

	ciphertext, err := encrypt(data, passphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := ioutil.WriteFile(dataFile, ciphertext, 0644); err != nil {
		return fmt.Errorf("failed to write datafile: %v", err)
	}

	return nil
}

// deleteSecret removes a secret from the Secrets map.
func deleteSecret(secrets Secrets, name string) {
	delete(secrets, name)
}

func main() {
	var passphrase string
	fmt.Print("Enter passphrase to unlock the datafile: ")
	fmt.Scanln(&passphrase)

	// Check if recovery key exists
	if _, err := os.Stat(recoveryFile); os.IsNotExist(err) {
		var masterPassword string
		fmt.Print("No recovery key found. Enter a master password to generate one: ")
		fmt.Scanln(&masterPassword)
		if err := setupRecovery(masterPassword); err != nil {
			fmt.Printf("Error setting up recovery: %v\n", err)
			return
		}
	}

	secrets, err := loadSecrets(passphrase)
	if err != nil {
		fmt.Printf("Error loading secrets: %v\n", err)
		fmt.Println("Attempting recovery with master password...")

		var masterPassword string
		fmt.Print("Enter master password: ")
		fmt.Scanln(&masterPassword)

		recoveryKey, err := recoverWithMasterPassword(masterPassword)
		if err != nil {
			fmt.Printf("Recovery failed: %v\n", err)
			return
		}

		fmt.Println("Recovery successful! Please set a new passphrase.")
		secrets, err = loadSecrets(string(recoveryKey))
		if err != nil {
			fmt.Printf("Error loading secrets with recovery key: %v\n", err)
			return
		}

		fmt.Print("Enter a new passphrase: ")
		fmt.Scanln(&passphrase)
		if err := saveSecrets(secrets, passphrase); err != nil {
			fmt.Printf("Error saving secrets: %v\n", err)
			return
		}
	}

	for {
		fmt.Println("\nTOTP Tokens:")
		for name, secret := range secrets {
			otp, err := GenerateTOTP(secret)
			if err != nil {
				fmt.Printf("Error generating TOTP for %s: %v\n", name, err)
				continue
			}
			fmt.Printf("%s: %s\n", name, otp)
		}

		fmt.Println("\n1. Add new secret")
		fmt.Println("2. Delete secret")
		fmt.Println("3. Exit")
		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1: // Add new secret
			var name, secret string
			fmt.Print("Enter account name: ")
			fmt.Scanln(&name)
			fmt.Print("Enter TOTP secret: ")
			fmt.Scanln(&secret)
			secrets[name] = secret
			if err := saveSecrets(secrets, passphrase); err != nil {
				fmt.Printf("Error saving secrets: %v\n", err)
			}

		case 2: // Delete secret
			var name string
			fmt.Print("Enter account name to delete: ")
			fmt.Scanln(&name)
			if _, exists := secrets[name]; exists {
				deleteSecret(secrets, name)
				if err := saveSecrets(secrets, passphrase); err != nil {
					fmt.Printf("Error saving secrets: %v\n", err)
				} else {
					fmt.Printf("Secret for %s deleted successfully.\n", name)
				}
			} else {
				fmt.Printf("No secret found for %s.\n", name)
			}

		case 3: // Exit
			return

		default:
			fmt.Println("Invalid choice. Please try again.")
		}

		time.Sleep(1 * time.Second)
	}
}
