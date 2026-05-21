package app

import (
	"context"
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
	now      func() time.Time
}

func New(cfg config.Config, st *store.Store, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	return &App{
		cfg:    cfg,
		store:  st,
		logger: logger,
		envelope: configcrypto.Envelope{
			MasterKey: cfg.MasterKey,
			KeyID:     cfg.KeyID,
		},
		now: time.Now,
	}, nil
}

type RegisterInput struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"`
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
	user, err := a.store.CreateUser(ctx, username, string(hash))
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

func (a *App) Logout(ctx context.Context, userID string) {
	a.audit(ctx, userID, "logout", "user", userID, nil)
}

type ConfigInput struct {
	Key         string             `json:"key"`
	Value       string             `json:"value"`
	Application string             `json:"application"`
	Environment string             `json:"environment"`
	Description string             `json:"description"`
	Status      store.ConfigStatus `json:"status"`
}

func (a *App) CreateConfig(ctx context.Context, userID string, input ConfigInput) (store.Config, error) {
	if err := validateConfigInput(input, true); err != nil {
		return store.Config{}, err
	}
	payload, err := a.envelope.Encrypt([]byte(input.Value))
	if err != nil {
		return store.Config{}, err
	}
	config, err := a.store.CreateConfig(ctx, store.CreateConfigParams{
		UserID:      userID,
		Key:         strings.TrimSpace(input.Key),
		Application: strings.TrimSpace(input.Application),
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
	return config, nil
}

func (a *App) UpdateConfig(ctx context.Context, userID, configID string, input ConfigInput) (store.Config, error) {
	if strings.TrimSpace(configID) == "" {
		return store.Config{}, BadField("id", "is required")
	}
	if err := validateConfigInput(input, true); err != nil {
		return store.Config{}, err
	}
	payload, err := a.envelope.Encrypt([]byte(input.Value))
	if err != nil {
		return store.Config{}, err
	}
	config, err := a.store.UpdateConfig(ctx, store.UpdateConfigParams{
		UserID:      userID,
		ConfigID:    configID,
		Key:         strings.TrimSpace(input.Key),
		Application: strings.TrimSpace(input.Application),
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
	return config, nil
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
	return a.store.ListConfigs(ctx, store.ListConfigsParams{
		UserID:      userID,
		Application: strings.TrimSpace(application),
		Environment: strings.TrimSpace(environment),
		Limit:       limit,
		Offset:      offset,
	})
}

func (a *App) ListVersions(ctx context.Context, userID, configID string) ([]store.Config, error) {
	if strings.TrimSpace(configID) == "" {
		return nil, BadField("id", "is required")
	}
	return a.store.ListConfigVersions(ctx, userID, configID)
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
	return config, nil
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
	return a.store.ListActiveConfigs(ctx, userID, strings.TrimSpace(application), strings.TrimSpace(environment))
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
	if strings.TrimSpace(input.Key) == "" {
		return BadField("key", "is required")
	}
	if strings.TrimSpace(input.Application) == "" {
		return BadField("application", "is required")
	}
	if strings.TrimSpace(input.Environment) == "" {
		return BadField("environment", "is required")
	}
	if requireValue && input.Value == "" {
		return BadField("value", "is required")
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
