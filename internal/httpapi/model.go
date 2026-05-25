package httpapi

import (
	"time"

	"simple-config-service/internal/store"
	"simple-config-service/pkg/configcrypto"
)

type configResponse struct {
	ID             string               `json:"id"`
	ProjectID      string               `json:"project_id"`
	ProjectName    string               `json:"project_name"`
	Key            string               `json:"key"`
	Application    string               `json:"application"`
	Environment    string               `json:"environment"`
	Description    string               `json:"description"`
	EncryptedValue configcrypto.Payload `json:"encrypted_value"`
	Version        int                  `json:"version"`
	Status         store.ConfigStatus   `json:"status"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

type internalConfigResponse struct {
	ProjectID      string               `json:"project_id"`
	ProjectName    string               `json:"project_name"`
	Key            string               `json:"key"`
	EncryptedValue configcrypto.Payload `json:"encrypted_value"`
	Version        int                  `json:"version"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

type projectResponse struct {
	ID                      string    `json:"id"`
	Name                    string    `json:"name"`
	Description             string    `json:"description"`
	RSAPublicKey            string    `json:"rsa_public_key"`
	RSAPublicKeyFingerprint string    `json:"rsa_public_key_fingerprint"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func toConfigResponse(config store.Config) configResponse {
	return configResponse{
		ID:          config.ID,
		ProjectID:   config.ProjectID,
		ProjectName: config.ProjectName,
		Key:         config.Key,
		Application: config.Application,
		Environment: config.Environment,
		Description: config.Description,
		EncryptedValue: configcrypto.Payload{
			ValueCiphertext:  config.ValueCiphertext,
			EncryptedDataKey: config.EncryptedDataKey,
			Nonce:            config.Nonce,
			DataKeyNonce:     config.DataKeyNonce,
			Algorithm:        config.Algorithm,
			KeyID:            config.KeyID,
		},
		Version:   config.Version,
		Status:    config.Status,
		CreatedAt: config.CreatedAt,
		UpdatedAt: config.UpdatedAt,
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
			ProjectID:   config.ProjectID,
			ProjectName: config.ProjectName,
			Key:         config.Key,
			EncryptedValue: configcrypto.Payload{
				ValueCiphertext:  config.ValueCiphertext,
				EncryptedDataKey: config.EncryptedDataKey,
				Nonce:            config.Nonce,
				DataKeyNonce:     config.DataKeyNonce,
				Algorithm:        config.Algorithm,
				KeyID:            config.KeyID,
			},
			Version:   config.Version,
			UpdatedAt: config.UpdatedAt,
		})
	}
	return responses
}

func toProjectResponse(project store.Project) projectResponse {
	return projectResponse{
		ID:                      project.ID,
		Name:                    project.Name,
		Description:             project.Description,
		RSAPublicKey:            project.RSAPublicKeyPEM,
		RSAPublicKeyFingerprint: project.RSAPublicKeyFingerprint,
		CreatedAt:               project.CreatedAt,
		UpdatedAt:               project.UpdatedAt,
	}
}

func toProjectResponses(projects []store.Project) []projectResponse {
	responses := make([]projectResponse, 0, len(projects))
	for _, project := range projects {
		responses = append(responses, toProjectResponse(project))
	}
	return responses
}
