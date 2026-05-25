package configcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	AlgorithmAES256GCM = "AES-256-GCM"
	AlgorithmRSAOAEP   = "RSA-OAEP-SHA256+A256GCM"
	dataKeySize        = 32
	nonceSize          = 12
	defaultRSAKeyBits  = 3072
)

type Payload struct {
	ValueCiphertext  string `json:"value_ciphertext"`
	EncryptedDataKey string `json:"encrypted_data_key"`
	Nonce            string `json:"nonce"`
	DataKeyNonce     string `json:"data_key_nonce,omitempty"`
	Algorithm        string `json:"algorithm"`
	KeyID            string `json:"key_id"`
}

type Envelope struct {
	MasterKey []byte
	KeyID     string
}

func ParseMasterKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("master key is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) == dataKeySize {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(decoded) == dataKeySize {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == dataKeySize {
		return decoded, nil
	}
	if len([]byte(value)) == dataKeySize {
		return []byte(value), nil
	}
	return nil, errors.New("master key must be 32 raw bytes, 32-byte hex, or 32-byte base64")
}

func (e Envelope) Encrypt(plaintext []byte) (Payload, error) {
	if len(e.MasterKey) != dataKeySize {
		return Payload{}, fmt.Errorf("master key must be %d bytes", dataKeySize)
	}

	dataKey := make([]byte, dataKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Payload{}, err
	}
	defer zero(dataKey)

	valueNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, valueNonce); err != nil {
		return Payload{}, err
	}
	valueCiphertext, err := encryptAESGCM(dataKey, valueNonce, plaintext)
	if err != nil {
		return Payload{}, err
	}

	dataKeyNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, dataKeyNonce); err != nil {
		return Payload{}, err
	}
	encryptedDataKey, err := encryptAESGCM(e.MasterKey, dataKeyNonce, dataKey)
	if err != nil {
		return Payload{}, err
	}

	keyID := e.KeyID
	if keyID == "" {
		keyID = "default"
	}
	return Payload{
		ValueCiphertext:  base64.StdEncoding.EncodeToString(valueCiphertext),
		EncryptedDataKey: base64.StdEncoding.EncodeToString(encryptedDataKey),
		Nonce:            base64.StdEncoding.EncodeToString(valueNonce),
		DataKeyNonce:     base64.StdEncoding.EncodeToString(dataKeyNonce),
		Algorithm:        AlgorithmAES256GCM,
		KeyID:            keyID,
	}, nil
}

func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, defaultRSAKeyBits)
}

func LoadOrCreateRSAKeyPair(privatePath, publicPath string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(privatePath) == "" || strings.TrimSpace(publicPath) == "" {
		return nil, errors.New("private and public key paths are required")
	}

	privatePEM, privateErr := os.ReadFile(privatePath)
	publicPEM, publicErr := os.ReadFile(publicPath)
	if privateErr == nil && publicErr == nil {
		privateKey, err := ParseRSAPrivateKeyPEM(string(privatePEM))
		if err != nil {
			return nil, fmt.Errorf("parse service private key: %w", err)
		}
		publicKey, err := ParseRSAPublicKeyPEM(string(publicPEM))
		if err != nil {
			return nil, fmt.Errorf("parse service public key: %w", err)
		}
		if PublicKeyFingerprint(&privateKey.PublicKey) != PublicKeyFingerprint(publicKey) {
			return nil, errors.New("service public key does not match private key")
		}
		return privateKey, nil
	}
	if privateErr == nil && errors.Is(publicErr, os.ErrNotExist) {
		privateKey, err := ParseRSAPrivateKeyPEM(string(privatePEM))
		if err != nil {
			return nil, fmt.Errorf("parse service private key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(publicPath, []byte(EncodeRSAPublicKeyPEM(&privateKey.PublicKey)), 0o644); err != nil {
			return nil, err
		}
		return privateKey, nil
	}
	if errors.Is(privateErr, os.ErrNotExist) && publicErr == nil {
		return nil, errors.New("service private key is missing")
	}
	if privateErr != nil && !errors.Is(privateErr, os.ErrNotExist) {
		return nil, privateErr
	}
	if publicErr != nil && !errors.Is(publicErr, os.ErrNotExist) {
		return nil, publicErr
	}

	privateKey, err := GenerateRSAKeyPair()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(privatePath, []byte(EncodeRSAPrivateKeyPEM(privateKey)), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(publicPath, []byte(EncodeRSAPublicKeyPEM(&privateKey.PublicKey)), 0o644); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func EncodeRSAPrivateKeyPEM(privateKey *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func EncodeRSAPublicKeyPEM(publicKey *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ParseRSAPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("private key must be PEM encoded")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return privateKey, privateKey.Validate()
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		return privateKey, privateKey.Validate()
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}

func ParseRSAPublicKeyPEM(value string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("public key must be PEM encoded")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}
		return publicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported public key type %q", block.Type)
	}
}

func PublicKeyFingerprint(publicKey *rsa.PublicKey) string {
	if publicKey == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

func RSAKeyID(prefix string, publicKey *rsa.PublicKey) string {
	fingerprint := PublicKeyFingerprint(publicKey)
	if prefix == "" {
		return fingerprint
	}
	return prefix + ":" + fingerprint
}

func EncryptRSAEnvelope(publicKey *rsa.PublicKey, plaintext []byte, keyID string) (Payload, error) {
	if publicKey == nil {
		return Payload{}, errors.New("public key is required")
	}
	dataKey := make([]byte, dataKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Payload{}, err
	}
	defer zero(dataKey)

	valueNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, valueNonce); err != nil {
		return Payload{}, err
	}
	valueCiphertext, err := encryptAESGCM(dataKey, valueNonce, plaintext)
	if err != nil {
		return Payload{}, err
	}
	encryptedDataKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dataKey, nil)
	if err != nil {
		return Payload{}, err
	}
	if keyID == "" {
		keyID = PublicKeyFingerprint(publicKey)
	}
	return Payload{
		ValueCiphertext:  base64.StdEncoding.EncodeToString(valueCiphertext),
		EncryptedDataKey: base64.StdEncoding.EncodeToString(encryptedDataKey),
		Nonce:            base64.StdEncoding.EncodeToString(valueNonce),
		Algorithm:        AlgorithmRSAOAEP,
		KeyID:            keyID,
	}, nil
}

func DecryptRSAEnvelope(privateKey *rsa.PrivateKey, payload Payload) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if payload.Algorithm != AlgorithmRSAOAEP {
		return nil, fmt.Errorf("unsupported algorithm %q", payload.Algorithm)
	}
	encryptedDataKey, err := decodeBase64(payload.EncryptedDataKey, "encrypted_data_key")
	if err != nil {
		return nil, err
	}
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedDataKey, nil)
	if err != nil {
		return nil, err
	}
	defer zero(dataKey)

	valueCiphertext, err := decodeBase64(payload.ValueCiphertext, "value_ciphertext")
	if err != nil {
		return nil, err
	}
	valueNonce, err := decodeBase64(payload.Nonce, "nonce")
	if err != nil {
		return nil, err
	}
	return decryptAESGCM(dataKey, valueNonce, valueCiphertext)
}

func Decrypt(masterKey []byte, payload Payload) ([]byte, error) {
	if len(masterKey) != dataKeySize {
		return nil, fmt.Errorf("master key must be %d bytes", dataKeySize)
	}
	if payload.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("unsupported algorithm %q", payload.Algorithm)
	}

	encryptedDataKey, err := decodeBase64(payload.EncryptedDataKey, "encrypted_data_key")
	if err != nil {
		return nil, err
	}
	dataKeyNonce, err := decodeBase64(payload.DataKeyNonce, "data_key_nonce")
	if err != nil {
		return nil, err
	}
	dataKey, err := decryptAESGCM(masterKey, dataKeyNonce, encryptedDataKey)
	if err != nil {
		return nil, err
	}
	defer zero(dataKey)

	valueCiphertext, err := decodeBase64(payload.ValueCiphertext, "value_ciphertext")
	if err != nil {
		return nil, err
	}
	valueNonce, err := decodeBase64(payload.Nonce, "nonce")
	if err != nil {
		return nil, err
	}
	return decryptAESGCM(dataKey, valueNonce, valueCiphertext)
}

func encryptAESGCM(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func decryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decodeBase64(value, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", field, err)
	}
	return decoded, nil
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
