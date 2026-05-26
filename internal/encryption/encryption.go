package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize    = 16
	nonceSize   = 12
	keySize     = 32
	pbkdf2Iters = 100000
)

func DeriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, keySize, sha256.New)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

func EncryptString(key []byte, s string) (string, error) {
	ciphertext, err := Encrypt(key, []byte(s))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciphertext), nil
}

func DecryptString(key []byte, s string) (string, error) {
	ciphertext, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("key must be %d bytes", keySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
