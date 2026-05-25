package app

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"simple-config-service/internal/config"
	"simple-config-service/internal/store"
	"simple-config-service/pkg/configcrypto"
)

type App struct {
	cfg      config.Config
	store    *store.Store
	logger   *slog.Logger
	envelope configcrypto.Envelope
	service  *rsa.PrivateKey
	now      func() time.Time
}

func New(cfg config.Config, st *store.Store, logger *slog.Logger, servicePrivateKey *rsa.PrivateKey) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if servicePrivateKey == nil {
		return nil, errors.New("service private key is required")
	}
	return &App{
		cfg:     cfg,
		store:   st,
		logger:  logger,
		service: servicePrivateKey,
		envelope: configcrypto.Envelope{
			MasterKey: cfg.MasterKey,
			KeyID:     cfg.KeyID,
		},
		now: time.Now,
	}, nil
}

type RegisterInput struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	InviteCode    string `json:"invite_code"`
	RSAPrivateKey string `json:"rsa_private_key"`
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	AccessToken string     `json:"access_token"`
	TokenType   string     `json:"token_type"`
	ExpiresAt   time.Time  `json:"expires_at"`
	User        PublicUser `json:"user"`
}

type PublicUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type PublicKeyResponse struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	RSAPublicKey string `json:"rsa_public_key"`
}

type RotateUserRSAKeyInput struct {
	RSAPrivateKey string `json:"rsa_private_key"`
}

type ProjectInput struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	RSAPublicKey string `json:"rsa_public_key"`
}

type ProjectPublicKeyInput struct {
	RSAPublicKey string `json:"rsa_public_key"`
}

func (a *App) Register(ctx context.Context, input RegisterInput) (AuthResponse, error) {
	username := normalizeName(input.Username)
	if err := validateUsername(username); err != nil {
		return AuthResponse{}, err
	}
	if err := validatePassword(input.Password); err != nil {
		return AuthResponse{}, err
	}
	if subtle.ConstantTimeCompare([]byte(input.InviteCode), []byte(a.cfg.InviteCode)) != 1 {
		return AuthResponse{}, ErrForbidden
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return AuthResponse{}, err
	}
	privateKey, privateKeyPEM, err := parseOrGeneratePrivateKey(input.RSAPrivateKey)
	if err != nil {
		return AuthResponse{}, BadField("rsa_private_key", err.Error())
	}
	privateKeyPayload, err := a.encryptForService([]byte(privateKeyPEM))
	if err != nil {
		return AuthResponse{}, err
	}
	publicKeyPEM := configcrypto.EncodeRSAPublicKeyPEM(&privateKey.PublicKey)
	user, err := a.store.CreateUserWithKeys(ctx, store.CreateUserParams{
		Username:             username,
		PasswordHash:         string(hash),
		PrivateKeyPayload:    privateKeyPayload,
		PublicKeyPEM:         publicKeyPEM,
		PublicKeyFingerprint: configcrypto.PublicKeyFingerprint(&privateKey.PublicKey),
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return AuthResponse{}, ErrConflict
		}
		return AuthResponse{}, err
	}
	a.audit(ctx, user.ID, "register", "user", user.ID, nil)
	return a.authResponse(user)
}

func (a *App) Login(ctx context.Context, input LoginInput) (AuthResponse, error) {
	username := normalizeName(input.Username)
	user, err := a.store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return AuthResponse{}, ErrUnauthorized
		}
		return AuthResponse{}, err
	}
	if user.Status != "active" {
		return AuthResponse{}, ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return AuthResponse{}, ErrUnauthorized
	}
	a.audit(ctx, user.ID, "login", "user", user.ID, nil)
	return a.authResponse(user)
}

func (a *App) Refresh(ctx context.Context, token string) (AuthResponse, error) {
	claims, err := verifyToken(a.cfg.JWTSecret, token, a.now())
	if err != nil {
		return AuthResponse{}, err
	}
	user, err := a.store.GetUserByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return AuthResponse{}, ErrUnauthorized
		}
		return AuthResponse{}, err
	}
	if user.Status != "active" {
		return AuthResponse{}, ErrUnauthorized
	}
	return a.authResponse(user)
}

func (a *App) Authenticate(ctx context.Context, authHeader string) (PublicUser, error) {
	token, err := bearerToken(authHeader)
	if err != nil {
		return PublicUser{}, err
	}
	claims, err := verifyToken(a.cfg.JWTSecret, token, a.now())
	if err != nil {
		return PublicUser{}, err
	}
	user, err := a.store.GetUserByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return PublicUser{}, ErrUnauthorized
		}
		return PublicUser{}, err
	}
	if user.Status != "active" {
		return PublicUser{}, ErrUnauthorized
	}
	return publicUser(user), nil
}

func (a *App) GetUserPublicKey(ctx context.Context, userID string) (PublicKeyResponse, error) {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return PublicKeyResponse{}, ErrNotFound
		}
		return PublicKeyResponse{}, err
	}
	user, err = a.ensureUserRSAKey(ctx, user)
	if err != nil {
		return PublicKeyResponse{}, err
	}
	return userPublicKeyResponse(user), nil
}

func (a *App) RotateUserRSAPrivateKey(ctx context.Context, userID string, input RotateUserRSAKeyInput) (PublicKeyResponse, error) {
	privateKey, privateKeyPEM, err := parseOrGeneratePrivateKey(input.RSAPrivateKey)
	if err != nil {
		return PublicKeyResponse{}, BadField("rsa_private_key", err.Error())
	}
	privateKeyPayload, err := a.encryptForService([]byte(privateKeyPEM))
	if err != nil {
		return PublicKeyResponse{}, err
	}
	user, err := a.store.UpdateUserRSAKey(ctx, userID, privateKeyPayload, configcrypto.EncodeRSAPublicKeyPEM(&privateKey.PublicKey), configcrypto.PublicKeyFingerprint(&privateKey.PublicKey))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return PublicKeyResponse{}, ErrNotFound
		}
		return PublicKeyResponse{}, err
	}
	a.audit(ctx, userID, "rotate_user_rsa_private_key", "user", userID, map[string]any{"fingerprint": user.RSAPublicKeyFingerprint})
	return userPublicKeyResponse(user), nil
}

func (a *App) CreateProject(ctx context.Context, userID string, input ProjectInput) (store.Project, error) {
	name := strings.TrimSpace(input.Name)
	if err := validateProjectName(name); err != nil {
		return store.Project{}, err
	}
	publicKey, publicKeyPEM, err := parsePublicKey(input.RSAPublicKey)
	if err != nil {
		return store.Project{}, BadField("rsa_public_key", err.Error())
	}
	project, err := a.store.CreateProject(ctx, store.CreateProjectParams{
		UserID:                  userID,
		Name:                    name,
		Description:             strings.TrimSpace(input.Description),
		RSAPublicKeyPEM:         publicKeyPEM,
		RSAPublicKeyFingerprint: configcrypto.PublicKeyFingerprint(publicKey),
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Project{}, ErrConflict
		}
		return store.Project{}, err
	}
	a.audit(ctx, userID, "create_project", "project", project.ID, map[string]any{"name": project.Name})
	return project, nil
}

func (a *App) ListProjects(ctx context.Context, userID string) ([]store.Project, error) {
	return a.store.ListProjects(ctx, userID)
}

func (a *App) UpdateProjectRSAKey(ctx context.Context, userID, projectID string, input ProjectPublicKeyInput) (store.Project, error) {
	if strings.TrimSpace(projectID) == "" {
		return store.Project{}, BadField("id", "is required")
	}
	publicKey, publicKeyPEM, err := parsePublicKey(input.RSAPublicKey)
	if err != nil {
		return store.Project{}, BadField("rsa_public_key", err.Error())
	}
	project, err := a.store.UpdateProjectRSAKey(ctx, userID, projectID, publicKeyPEM, configcrypto.PublicKeyFingerprint(publicKey))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Project{}, ErrNotFound
		}
		return store.Project{}, err
	}
	a.audit(ctx, userID, "rotate_project_rsa_public_key", "project", project.ID, map[string]any{"fingerprint": project.RSAPublicKeyFingerprint})
	return project, nil
}

func (a *App) Logout(ctx context.Context, userID string) {
	a.audit(ctx, userID, "logout", "user", userID, nil)
}

type ConfigInput struct {
	ProjectID      string               `json:"project_id"`
	Key            string               `json:"key"`
	EncryptedValue configcrypto.Payload `json:"encrypted_value"`
	Application    string               `json:"application"`
	Environment    string               `json:"environment"`
	Description    string               `json:"description"`
	Status         store.ConfigStatus   `json:"status"`
}

func (a *App) CreateConfig(ctx context.Context, userID string, input ConfigInput) (store.Config, error) {
	if err := validateConfigInput(input, true); err != nil {
		return store.Config{}, err
	}
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return store.Config{}, err
	}
	user, err = a.ensureUserRSAKey(ctx, user)
	if err != nil {
		return store.Config{}, err
	}
	project, err := a.store.GetProjectByID(ctx, userID, strings.TrimSpace(input.ProjectID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Config{}, ErrNotFound
		}
		return store.Config{}, err
	}
	plaintext, err := a.decryptClientValue(user, input.EncryptedValue)
	if err != nil {
		return store.Config{}, err
	}
	payload, err := a.encryptForService(plaintext)
	if err != nil {
		return store.Config{}, err
	}
	config, err := a.store.CreateConfig(ctx, store.CreateConfigParams{
		UserID:      userID,
		ProjectID:   project.ID,
		Key:         strings.TrimSpace(input.Key),
		Application: project.Name,
		Environment: strings.TrimSpace(input.Environment),
		Description: strings.TrimSpace(input.Description),
		Status:      normalizeStatus(input.Status),
		Payload:     payload,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Config{}, ErrConflict
		}
		return store.Config{}, err
	}
	a.audit(ctx, userID, "create_config", "config", config.ID, map[string]any{"key": config.Key})
	return a.encryptConfigForProject(ctx, userID, config)
}

func (a *App) UpdateConfig(ctx context.Context, userID, configID string, input ConfigInput) (store.Config, error) {
	if strings.TrimSpace(configID) == "" {
		return store.Config{}, BadField("id", "is required")
	}
	if err := validateConfigInput(input, true); err != nil {
		return store.Config{}, err
	}
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return store.Config{}, err
	}
	user, err = a.ensureUserRSAKey(ctx, user)
	if err != nil {
		return store.Config{}, err
	}
	project, err := a.store.GetProjectByID(ctx, userID, strings.TrimSpace(input.ProjectID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Config{}, ErrNotFound
		}
		return store.Config{}, err
	}
	plaintext, err := a.decryptClientValue(user, input.EncryptedValue)
	if err != nil {
		return store.Config{}, err
	}
	payload, err := a.encryptForService(plaintext)
	if err != nil {
		return store.Config{}, err
	}
	config, err := a.store.UpdateConfig(ctx, store.UpdateConfigParams{
		UserID:      userID,
		ConfigID:    configID,
		ProjectID:   project.ID,
		Key:         strings.TrimSpace(input.Key),
		Application: project.Name,
		Environment: strings.TrimSpace(input.Environment),
		Description: strings.TrimSpace(input.Description),
		Status:      normalizeStatus(input.Status),
		Payload:     payload,
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Config{}, ErrNotFound
		}
		if errors.Is(err, store.ErrConflict) {
			return store.Config{}, ErrConflict
		}
		return store.Config{}, err
	}
	a.audit(ctx, userID, "update_config", "config", config.ID, map[string]any{"version": config.Version})
	return a.encryptConfigForProject(ctx, userID, config)
}

func (a *App) DeleteConfig(ctx context.Context, userID, configID string) error {
	if strings.TrimSpace(configID) == "" {
		return BadField("id", "is required")
	}
	if err := a.store.DeleteConfig(ctx, userID, configID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	a.audit(ctx, userID, "delete_config", "config", configID, nil)
	return nil
}

func (a *App) ListConfigs(ctx context.Context, userID, application, environment string, limit, offset int) ([]store.Config, error) {
	configs, err := a.store.ListConfigs(ctx, store.ListConfigsParams{
		UserID:      userID,
		Application: strings.TrimSpace(application),
		Environment: strings.TrimSpace(environment),
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		return nil, err
	}
	return a.encryptConfigsForProjects(ctx, userID, configs)
}

func (a *App) ListProjectConfigs(ctx context.Context, userID, projectID, environment string, limit, offset int) ([]store.Config, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, BadField("project_id", "is required")
	}
	configs, err := a.store.ListConfigs(ctx, store.ListConfigsParams{
		UserID:      userID,
		ProjectID:   strings.TrimSpace(projectID),
		Environment: strings.TrimSpace(environment),
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		return nil, err
	}
	return a.encryptConfigsForProjects(ctx, userID, configs)
}

func (a *App) ListVersions(ctx context.Context, userID, configID string) ([]store.Config, error) {
	if strings.TrimSpace(configID) == "" {
		return nil, BadField("id", "is required")
	}
	configs, err := a.store.ListConfigVersions(ctx, userID, configID)
	if err != nil {
		return nil, err
	}
	return a.encryptConfigsForProjects(ctx, userID, configs)
}

func (a *App) Rollback(ctx context.Context, userID, configID string, version int) (store.Config, error) {
	if strings.TrimSpace(configID) == "" {
		return store.Config{}, BadField("id", "is required")
	}
	if version <= 0 {
		return store.Config{}, BadField("version", "must be positive")
	}
	config, err := a.store.RollbackConfig(ctx, userID, configID, version)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Config{}, ErrNotFound
		}
		if errors.Is(err, store.ErrConflict) {
			return store.Config{}, ErrConflict
		}
		return store.Config{}, err
	}
	a.audit(ctx, userID, "rollback_config", "config", configID, map[string]any{"from_version": version, "new_version": config.Version})
	return a.encryptConfigForProject(ctx, userID, config)
}

func (a *App) InternalConfigs(ctx context.Context, userID, application, environment string) ([]store.Config, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, BadField("user_id", "is required")
	}
	if strings.TrimSpace(application) == "" {
		return nil, BadField("application", "is required")
	}
	if strings.TrimSpace(environment) == "" {
		return nil, BadField("environment", "is required")
	}
	configs, err := a.store.ListActiveConfigs(ctx, userID, strings.TrimSpace(application), strings.TrimSpace(environment))
	if err != nil {
		return nil, err
	}
	return a.encryptConfigsForProjects(ctx, userID, configs)
}

func (a *App) InternalProjectConfigs(ctx context.Context, userID, projectID, environment string) ([]store.Config, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, BadField("user_id", "is required")
	}
	if strings.TrimSpace(projectID) == "" {
		return nil, BadField("project_id", "is required")
	}
	if strings.TrimSpace(environment) == "" {
		return nil, BadField("environment", "is required")
	}
	configs, err := a.store.ListActiveProjectConfigs(ctx, userID, strings.TrimSpace(projectID), "", strings.TrimSpace(environment))
	if err != nil {
		return nil, err
	}
	return a.encryptConfigsForProjects(ctx, userID, configs)
}

func (a *App) Health(ctx context.Context) error {
	return a.store.Ping(ctx)
}

func (a *App) authResponse(user store.User) (AuthResponse, error) {
	token, claims, err := issueToken(a.cfg.JWTSecret, a.cfg.JWTTTL, user.ID, user.Username, a.now())
	if err != nil {
		return AuthResponse{}, err
	}
	return AuthResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Unix(claims.Expires, 0).UTC(),
		User:        publicUser(user),
	}, nil
}

func (a *App) audit(ctx context.Context, userID, action, resourceType, resourceID string, metadata map[string]any) {
	if err := a.store.Audit(ctx, userID, action, resourceType, resourceID, metadata); err != nil {
		a.logger.Warn("audit failed", "action", action, "error", err)
	}
}

func publicUser(user store.User) PublicUser {
	return PublicUser{
		ID:        user.ID,
		Username:  user.Username,
		Status:    user.Status,
		CreatedAt: user.CreatedAt,
	}
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateUsername(value string) error {
	if len(value) < 3 || len(value) > 64 {
		return BadField("username", "must be between 3 and 64 characters")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return BadField("username", "may contain only letters, numbers, underscore, dash, and dot")
	}
	return nil
}

func validatePassword(value string) error {
	if len(value) < 8 {
		return BadField("password", "must be at least 8 characters")
	}
	return nil
}

func validateConfigInput(input ConfigInput, requireValue bool) error {
	if strings.TrimSpace(input.ProjectID) == "" {
		return BadField("project_id", "is required")
	}
	if strings.TrimSpace(input.Key) == "" {
		return BadField("key", "is required")
	}
	if strings.TrimSpace(input.Environment) == "" {
		return BadField("environment", "is required")
	}
	if requireValue && !hasEncryptedValue(input.EncryptedValue) {
		return BadField("encrypted_value", "is required")
	}
	status := normalizeStatus(input.Status)
	if status != store.ConfigEnabled && status != store.ConfigDisabled {
		return BadField("status", "must be enabled or disabled")
	}
	return nil
}

func normalizeStatus(status store.ConfigStatus) store.ConfigStatus {
	if status == "" {
		return store.ConfigEnabled
	}
	return store.ConfigStatus(strings.ToLower(strings.TrimSpace(string(status))))
}

func (a *App) encryptForService(plaintext []byte) (configcrypto.Payload, error) {
	return configcrypto.EncryptRSAEnvelope(&a.service.PublicKey, plaintext, configcrypto.RSAKeyID("service", &a.service.PublicKey))
}

func (a *App) decryptServiceValue(payload configcrypto.Payload) ([]byte, error) {
	switch payload.Algorithm {
	case configcrypto.AlgorithmRSAOAEP:
		return configcrypto.DecryptRSAEnvelope(a.service, payload)
	case configcrypto.AlgorithmAES256GCM:
		if len(a.cfg.MasterKey) == 0 {
			return nil, errors.New("legacy config_master_key is required to decrypt AES payload")
		}
		return configcrypto.Decrypt(a.cfg.MasterKey, payload)
	default:
		return nil, BadField("algorithm", "is unsupported")
	}
}

func (a *App) decryptClientValue(user store.User, payload configcrypto.Payload) ([]byte, error) {
	if payload.Algorithm != configcrypto.AlgorithmRSAOAEP {
		return nil, BadField("encrypted_value", "must use RSA-OAEP-SHA256+A256GCM")
	}
	privateKeyPEM, err := a.decryptServiceValue(user.RSAPrivateKeyPayload)
	if err != nil {
		return nil, BadField("encrypted_value", "could not load user private key")
	}
	privateKey, err := configcrypto.ParseRSAPrivateKeyPEM(string(privateKeyPEM))
	if err != nil {
		return nil, BadField("encrypted_value", "stored user private key is invalid")
	}
	plaintext, err := configcrypto.DecryptRSAEnvelope(privateKey, payload)
	if err != nil {
		return nil, BadField("encrypted_value", "could not be decrypted")
	}
	return plaintext, nil
}

func (a *App) encryptConfigForProject(ctx context.Context, userID string, config store.Config) (store.Config, error) {
	if strings.TrimSpace(config.ProjectID) == "" {
		return config, nil
	}
	project, err := a.store.GetProjectByID(ctx, userID, config.ProjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Config{}, ErrNotFound
		}
		return store.Config{}, err
	}
	plaintext, err := a.decryptServiceValue(config.CryptoPayload)
	if err != nil {
		return store.Config{}, err
	}
	publicKey, err := configcrypto.ParseRSAPublicKeyPEM(project.RSAPublicKeyPEM)
	if err != nil {
		return store.Config{}, err
	}
	payload, err := configcrypto.EncryptRSAEnvelope(publicKey, plaintext, projectKeyID(project))
	if err != nil {
		return store.Config{}, err
	}
	config.ProjectName = project.Name
	applyPayload(&config, payload)
	return config, nil
}

func (a *App) encryptConfigsForProjects(ctx context.Context, userID string, configs []store.Config) ([]store.Config, error) {
	responses := make([]store.Config, 0, len(configs))
	projectCache := map[string]store.Project{}
	for _, config := range configs {
		if strings.TrimSpace(config.ProjectID) == "" {
			responses = append(responses, config)
			continue
		}
		project, ok := projectCache[config.ProjectID]
		if !ok {
			var err error
			project, err = a.store.GetProjectByID(ctx, userID, config.ProjectID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil, ErrNotFound
				}
				return nil, err
			}
			projectCache[config.ProjectID] = project
		}
		plaintext, err := a.decryptServiceValue(config.CryptoPayload)
		if err != nil {
			return nil, err
		}
		publicKey, err := configcrypto.ParseRSAPublicKeyPEM(project.RSAPublicKeyPEM)
		if err != nil {
			return nil, err
		}
		payload, err := configcrypto.EncryptRSAEnvelope(publicKey, plaintext, projectKeyID(project))
		if err != nil {
			return nil, err
		}
		config.ProjectName = project.Name
		applyPayload(&config, payload)
		responses = append(responses, config)
	}
	return responses, nil
}

func (a *App) ensureUserRSAKey(ctx context.Context, user store.User) (store.User, error) {
	if user.RSAPublicKeyPEM != "" && hasEncryptedValue(user.RSAPrivateKeyPayload) {
		return user, nil
	}
	privateKey, privateKeyPEM, err := parseOrGeneratePrivateKey("")
	if err != nil {
		return store.User{}, err
	}
	payload, err := a.encryptForService([]byte(privateKeyPEM))
	if err != nil {
		return store.User{}, err
	}
	updated, err := a.store.UpdateUserRSAKey(ctx, user.ID, payload, configcrypto.EncodeRSAPublicKeyPEM(&privateKey.PublicKey), configcrypto.PublicKeyFingerprint(&privateKey.PublicKey))
	if err != nil {
		return store.User{}, err
	}
	return updated, nil
}

func parseOrGeneratePrivateKey(value string) (*rsa.PrivateKey, string, error) {
	if strings.TrimSpace(value) == "" {
		privateKey, err := configcrypto.GenerateRSAKeyPair()
		if err != nil {
			return nil, "", err
		}
		return privateKey, configcrypto.EncodeRSAPrivateKeyPEM(privateKey), nil
	}
	privateKey, err := configcrypto.ParseRSAPrivateKeyPEM(value)
	if err != nil {
		return nil, "", err
	}
	return privateKey, configcrypto.EncodeRSAPrivateKeyPEM(privateKey), nil
}

func parsePublicKey(value string) (*rsa.PublicKey, string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, "", errors.New("is required")
	}
	publicKey, err := configcrypto.ParseRSAPublicKeyPEM(value)
	if err != nil {
		return nil, "", err
	}
	return publicKey, configcrypto.EncodeRSAPublicKeyPEM(publicKey), nil
}

func userPublicKeyResponse(user store.User) PublicKeyResponse {
	keyID := "user:" + user.ID + ":" + user.RSAPublicKeyFingerprint
	return PublicKeyResponse{
		Algorithm:    configcrypto.AlgorithmRSAOAEP,
		KeyID:        keyID,
		RSAPublicKey: user.RSAPublicKeyPEM,
	}
}

func validateProjectName(value string) error {
	if len(value) < 1 || len(value) > 128 {
		return BadField("name", "must be between 1 and 128 characters")
	}
	return nil
}

func hasEncryptedValue(payload configcrypto.Payload) bool {
	return strings.TrimSpace(payload.Algorithm) != "" &&
		strings.TrimSpace(payload.EncryptedDataKey) != "" &&
		strings.TrimSpace(payload.Nonce) != "" &&
		strings.TrimSpace(payload.ValueCiphertext) != ""
}

func applyPayload(config *store.Config, payload configcrypto.Payload) {
	config.ValueCiphertext = payload.ValueCiphertext
	config.EncryptedDataKey = payload.EncryptedDataKey
	config.Nonce = payload.Nonce
	config.DataKeyNonce = payload.DataKeyNonce
	config.Algorithm = payload.Algorithm
	config.KeyID = payload.KeyID
	config.CryptoPayload = payload
}

func projectKeyID(project store.Project) string {
	return "project:" + project.ID + ":" + project.RSAPublicKeyFingerprint
}
