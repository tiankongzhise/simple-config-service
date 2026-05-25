package configcrypto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestRSAEnvelopeEncryptDecryptLongValue(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	plaintext := []byte(strings.Repeat("secret-value-", 1024))

	payload, err := EncryptRSAEnvelope(&privateKey.PublicKey, plaintext, "test-key")
	if err != nil {
		t.Fatalf("encrypt rsa envelope: %v", err)
	}
	if payload.Algorithm != AlgorithmRSAOAEP {
		t.Fatalf("unexpected algorithm %q", payload.Algorithm)
	}
	if payload.DataKeyNonce != "" {
		t.Fatalf("rsa payload should not include data key nonce")
	}

	decrypted, err := DecryptRSAEnvelope(privateKey, payload)
	if err != nil {
		t.Fatalf("decrypt rsa envelope: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("unexpected rsa plaintext")
	}
}

func TestRSAEnvelopeDecryptWithWrongKeyFails(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongKey, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	payload, err := EncryptRSAEnvelope(&privateKey.PublicKey, []byte("secret"), "test-key")
	if err != nil {
		t.Fatalf("encrypt rsa envelope: %v", err)
	}
	if _, err := DecryptRSAEnvelope(wrongKey, payload); err == nil {
		t.Fatal("expected decrypt with wrong rsa key to fail")
	}
}

func TestRSAPEMRoundTripAndFingerprint(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privatePEM := EncodeRSAPrivateKeyPEM(privateKey)
	publicPEM := EncodeRSAPublicKeyPEM(&privateKey.PublicKey)
	if !strings.Contains(privatePEM, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected PKCS#8 private key pem, got %q", privatePEM[:32])
	}

	parsedPrivate, err := ParseRSAPrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	parsedPublic, err := ParseRSAPublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if PublicKeyFingerprint(&parsedPrivate.PublicKey) != PublicKeyFingerprint(parsedPublic) {
		t.Fatal("fingerprint mismatch after pem round trip")
	}
}

func TestLoadOrCreateRSAKeyPair(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "keys", "service_private.pem")
	publicPath := filepath.Join(dir, "keys", "service_public.pem")

	privateKey, err := LoadOrCreateRSAKeyPair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("load or create: %v", err)
	}
	if _, err := os.Stat(privatePath); err != nil {
		t.Fatalf("private key not written: %v", err)
	}
	if _, err := os.Stat(publicPath); err != nil {
		t.Fatalf("public key not written: %v", err)
	}

	loadedKey, err := LoadOrCreateRSAKeyPair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("load existing: %v", err)
	}
	if PublicKeyFingerprint(&privateKey.PublicKey) != PublicKeyFingerprint(&loadedKey.PublicKey) {
		t.Fatal("loaded service key changed")
	}
}
