package encryption

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key1 := DeriveKey("passphrase", salt)
	key2 := DeriveKey("passphrase", salt)
	key3 := DeriveKey("passphrase", []byte("abcdef0123456789"))

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("expected deterministic key derivation")
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("expected different salt to derive different key")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}

	if len(salt1) != 16 || len(salt2) != 16 {
		t.Fatalf("unexpected salt lengths %d and %d", len(salt1), len(salt2))
	}
	if bytes.Equal(salt1, salt2) {
		t.Fatal("expected random salts")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintexts := [][]byte{
		[]byte("hello world"),
		{},
	}

	for _, plaintext := range plaintexts {
		ciphertext, err := Encrypt(key, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if len(ciphertext) <= 12 {
			t.Fatalf("expected nonce and ciphertext, got %d bytes", len(ciphertext))
		}

		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("unexpected plaintext %q", decrypted)
		}
	}
}

func TestEncryptStringDecryptString(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)

	for _, value := range []string{"secret", ""} {
		ciphertext, err := EncryptString(key, value)
		if err != nil {
			t.Fatal(err)
		}
		if ciphertext == value {
			t.Fatalf("expected ciphertext to differ from plaintext %q", value)
		}

		plaintext, err := DecryptString(key, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if plaintext != value {
			t.Fatalf("expected %q, got %q", value, plaintext)
		}
	}
}

func TestEncryptDecryptErrors(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x11}, 32)
	shortKey := []byte("short")

	if _, err := Encrypt(shortKey, []byte("plaintext")); err == nil {
		t.Fatal("expected invalid encrypt key error")
	}
	if _, err := Decrypt(shortKey, []byte("ciphertext")); err == nil {
		t.Fatal("expected invalid decrypt key error")
	}
	if _, err := Decrypt(validKey, nil); err == nil {
		t.Fatal("expected empty ciphertext error")
	}
	if _, err := Decrypt(validKey, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected truncated ciphertext error")
	}
	if _, err := DecryptString(validKey, "not-hex"); err == nil {
		t.Fatal("expected invalid hex error")
	}
	if _, err := DecryptString(validKey, ""); err == nil {
		t.Fatal("expected empty string ciphertext error")
	}

	ciphertext, err := Encrypt(validKey, []byte("tamper me"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := Decrypt(validKey, ciphertext); err == nil {
		t.Fatal("expected tampered ciphertext error")
	}
}
