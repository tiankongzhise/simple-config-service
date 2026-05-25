package app

import (
	"bytes"
	"testing"

	"simple-config-service/internal/config"
	"simple-config-service/internal/store"
	"simple-config-service/pkg/configcrypto"
)

func TestDecryptClientValueWithStoredUserPrivateKey(t *testing.T) {
	serviceKey, err := configcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate service key: %v", err)
	}
	userKey, err := configcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	a := &App{
		cfg:     config.Config{},
		service: serviceKey,
	}

	privateKeyPayload, err := a.encryptForService([]byte(configcrypto.EncodeRSAPrivateKeyPEM(userKey)))
	if err != nil {
		t.Fatalf("encrypt user private key: %v", err)
	}
	clientPayload, err := configcrypto.EncryptRSAEnvelope(&userKey.PublicKey, []byte("secret-value"), "user-key")
	if err != nil {
		t.Fatalf("encrypt client value: %v", err)
	}

	plaintext, err := a.decryptClientValue(store.User{RSAPrivateKeyPayload: privateKeyPayload}, clientPayload)
	if err != nil {
		t.Fatalf("decrypt client value: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("secret-value")) {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestServicePayloadCanBeReEncryptedForProjectKey(t *testing.T) {
	serviceKey, err := configcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate service key: %v", err)
	}
	projectKey, err := configcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate project key: %v", err)
	}
	a := &App{
		cfg:     config.Config{},
		service: serviceKey,
	}

	storedPayload, err := a.encryptForService([]byte("database-password"))
	if err != nil {
		t.Fatalf("encrypt for service: %v", err)
	}
	plaintext, err := a.decryptServiceValue(storedPayload)
	if err != nil {
		t.Fatalf("decrypt service payload: %v", err)
	}
	projectPayload, err := configcrypto.EncryptRSAEnvelope(&projectKey.PublicKey, plaintext, projectKeyID(store.Project{
		ID:                      "project-id",
		RSAPublicKeyFingerprint: configcrypto.PublicKeyFingerprint(&projectKey.PublicKey),
	}))
	if err != nil {
		t.Fatalf("encrypt for project: %v", err)
	}
	projectPlaintext, err := configcrypto.DecryptRSAEnvelope(projectKey, projectPayload)
	if err != nil {
		t.Fatalf("decrypt project payload: %v", err)
	}
	if !bytes.Equal(projectPlaintext, []byte("database-password")) {
		t.Fatalf("unexpected project plaintext %q", projectPlaintext)
	}
}

func TestParseOrGeneratePrivateKeyAcceptsProvidedPEM(t *testing.T) {
	privateKey, err := configcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	parsed, canonicalPEM, err := parseOrGeneratePrivateKey(configcrypto.EncodeRSAPrivateKeyPEM(privateKey))
	if err != nil {
		t.Fatalf("parse provided key: %v", err)
	}
	if configcrypto.PublicKeyFingerprint(&parsed.PublicKey) != configcrypto.PublicKeyFingerprint(&privateKey.PublicKey) {
		t.Fatal("parsed key fingerprint changed")
	}
	if canonicalPEM == "" {
		t.Fatal("expected canonical private key pem")
	}
}
