package configcrypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	envelope := Envelope{MasterKey: key, KeyID: "default"}

	first, err := envelope.Encrypt([]byte("secret-value"))
	if err != nil {
		t.Fatalf("encrypt first: %v", err)
	}
	second, err := envelope.Encrypt([]byte("secret-value"))
	if err != nil {
		t.Fatalf("encrypt second: %v", err)
	}
	if first.ValueCiphertext == second.ValueCiphertext {
		t.Fatal("expected same plaintext to produce different ciphertext")
	}

	plaintext, err := Decrypt(key, first)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("secret-value")) {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	wrongKey := []byte("abcdef0123456789abcdef0123456789")
	payload, err := (Envelope{MasterKey: key, KeyID: "default"}).Encrypt([]byte("secret-value"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(wrongKey, payload); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}
