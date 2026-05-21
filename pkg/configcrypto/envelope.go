package configcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	AlgorithmAES256GCM = "AES-256-GCM"
	dataKeySize        = 32
	nonceSize          = 12
)

type Payload struct {
	ValueCiphertext  string `json:"value_ciphertext"`
	EncryptedDataKey string `json:"encrypted_data_key"`
	Nonce            string `json:"nonce"`
	DataKeyNonce     string `json:"data_key_nonce"`
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
