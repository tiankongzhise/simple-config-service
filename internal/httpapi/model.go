package httpapi

import (
	"time"

	"simple-config-service/internal/store"
)

type configResponse struct {
	ID               string             `json:"id"`
	Key              string             `json:"key"`
	Application      string             `json:"application"`
	Environment      string             `json:"environment"`
	Description      string             `json:"description"`
	ValueCiphertext  string             `json:"value_ciphertext"`
	EncryptedDataKey string             `json:"encrypted_data_key"`
	Nonce            string             `json:"nonce"`
	DataKeyNonce     string             `json:"data_key_nonce"`
	Algorithm        string             `json:"algorithm"`
	KeyID            string             `json:"key_id"`
	Version          int                `json:"version"`
	Status           store.ConfigStatus `json:"status"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type internalConfigResponse struct {
	Key              string    `json:"key"`
	ValueCiphertext  string    `json:"value_ciphertext"`
	EncryptedDataKey string    `json:"encrypted_data_key"`
	Nonce            string    `json:"nonce"`
	DataKeyNonce     string    `json:"data_key_nonce"`
	Algorithm        string    `json:"algorithm"`
	KeyID            string    `json:"key_id"`
	Version          int       `json:"version"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func toConfigResponse(config store.Config) configResponse {
	return configResponse{
		ID:               config.ID,
		Key:              config.Key,
		Application:      config.Application,
		Environment:      config.Environment,
		Description:      config.Description,
		ValueCiphertext:  config.ValueCiphertext,
		EncryptedDataKey: config.EncryptedDataKey,
		Nonce:            config.Nonce,
		DataKeyNonce:     config.DataKeyNonce,
		Algorithm:        config.Algorithm,
		KeyID:            config.KeyID,
		Version:          config.Version,
		Status:           config.Status,
		CreatedAt:        config.CreatedAt,
		UpdatedAt:        config.UpdatedAt,
	}
}

func toConfigResponses(configs []store.Config) []configResponse {
	responses := make([]configResponse, 0, len(configs))
	for _, config := range configs {
		responses = append(responses, toConfigResponse(config))
	}
	return responses
}

func toInternalConfigResponses(configs []store.Config) []internalConfigResponse {
	responses := make([]internalConfigResponse, 0, len(configs))
	for _, config := range configs {
		responses = append(responses, internalConfigResponse{
			Key:              config.Key,
			ValueCiphertext:  config.ValueCiphertext,
			EncryptedDataKey: config.EncryptedDataKey,
			Nonce:            config.Nonce,
			DataKeyNonce:     config.DataKeyNonce,
			Algorithm:        config.Algorithm,
			KeyID:            config.KeyID,
			Version:          config.Version,
			UpdatedAt:        config.UpdatedAt,
		})
	}
	return responses
}
