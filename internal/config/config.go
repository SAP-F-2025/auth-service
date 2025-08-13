package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	JWT      JWTConfig      `json:"jwt"`
	OAuth    OAuthConfig    `json:"oauth"`
	Social   SocialConfig   `json:"social"`
	MFA      MFAConfig      `json:"mfa"`
	Email    EmailConfig    `json:"email"`
	Security SecurityConfig `json:"security"`
	Casdoor  CasdoorConfig  `json:"casdoor"`
}

type ServerConfig struct {
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	Environment  string        `json:"environment"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
	CORS         CORSConfig    `json:"cors"`
}

type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

type DatabaseConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	User         string        `json:"user"`
	Password     string        `json:"-"` // Hide from JSON
	Database     string        `json:"database"`
	SSLMode      string        `json:"ssl_mode"`
	MaxOpenConns int           `json:"max_open_conns"`
	MaxIdleConns int           `json:"max_idle_conns"`
	MaxLifetime  time.Duration `json:"max_lifetime"`
	MaxIdleTime  time.Duration `json:"max_idle_time"`
}

type RedisConfig struct {
	Host               string        `json:"host"`
	Port               int           `json:"port"`
	Password           string        `json:"-"` // Hide from JSON
	Database           int           `json:"database"`
	MaxRetries         int           `json:"max_retries"`
	MinRetryBackoff    time.Duration `json:"min_retry_backoff"`
	MaxRetryBackoff    time.Duration `json:"max_retry_backoff"`
	DialTimeout        time.Duration `json:"dial_timeout"`
	ReadTimeout        time.Duration `json:"read_timeout"`
	WriteTimeout       time.Duration `json:"write_timeout"`
	PoolSize           int           `json:"pool_size"`
	MinIdleConns       int           `json:"min_idle_conns"`
	MaxConnAge         time.Duration `json:"max_conn_age"`
	PoolTimeout        time.Duration `json:"pool_timeout"`
	IdleTimeout        time.Duration `json:"idle_timeout"`
	IdleCheckFrequency time.Duration `json:"idle_check_frequency"`
}

type JWTConfig struct {
	SecretKey            string        `json:"-"` // Hide from JSON
	AccessTokenExpiry    time.Duration `json:"access_token_expiry"`
	RefreshTokenExpiry   time.Duration `json:"refresh_token_expiry"`
	Issuer               string        `json:"issuer"`
	Audience             string        `json:"audience"`
	Algorithm            string        `json:"algorithm"`
	RefreshTokenRotation bool          `json:"refresh_token_rotation"`
}

type OAuthConfig struct {
	AuthorizationCodeExpiry time.Duration          `json:"authorization_code_expiry"`
	AccessTokenExpiry       time.Duration          `json:"access_token_expiry"`
	RefreshTokenExpiry      time.Duration          `json:"refresh_token_expiry"`
	Clients                 map[string]OAuthClient `json:"-"` // Hide from JSON
	Scopes                  []string               `json:"scopes"`
	PKCERequired            bool                   `json:"pkce_required"`
}

type OAuthClient struct {
	ClientSecret string   `json:"-"` // Hide from JSON
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	IsPublic     bool     `json:"is_public"`
	IsActive     bool     `json:"is_active"`
}

type SocialConfig struct {
	Google    GoogleConfig    `json:"google"`
	Microsoft MicrosoftConfig `json:"microsoft"`
}

type GoogleConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"` // Hide from JSON
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
}

type MicrosoftConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"-"` // Hide from JSON
	TenantID     string   `json:"tenant_id"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
}

type MFAConfig struct {
	Issuer               string        `json:"issuer"`
	TOTPWindowSize       int           `json:"totp_window_size"`
	BackupCodesCount     int           `json:"backup_codes_count"`
	BackupCodeLength     int           `json:"backup_code_length"`
	QRCodeSize           int           `json:"qr_code_size"`
	SetupTokenExpiry     time.Duration `json:"setup_token_expiry"`
	ChallengeTokenExpiry time.Duration `json:"challenge_token_expiry"`
	RequiredForRoles     []string      `json:"required_for_roles"`
}

type EmailConfig struct {
	SMTPHost            string        `json:"smtp_host"`
	SMTPPort            int           `json:"smtp_port"`
	SMTPUsername        string        `json:"smtp_username"`
	SMTPPassword        string        `json:"-"` // Hide from JSON
	FromEmail           string        `json:"from_email"`
	FromName            string        `json:"from_name"`
	UseTLS              bool          `json:"use_tls"`
	VerificationExpiry  time.Duration `json:"verification_expiry"`
	PasswordResetExpiry time.Duration `json:"password_reset_expiry"`
	MaxRetries          int           `json:"max_retries"`
	RetryDelay          time.Duration `json:"retry_delay"`
}

type SecurityConfig struct {
	PasswordMinLength        int           `json:"password_min_length"`
	PasswordRequireUppercase bool          `json:"password_require_uppercase"`
	PasswordRequireLowercase bool          `json:"password_require_lowercase"`
	PasswordRequireNumbers   bool          `json:"password_require_numbers"`
	PasswordRequireSpecial   bool          `json:"password_require_special"`
	BcryptCost               int           `json:"bcrypt_cost"`
	LoginMaxAttempts         int           `json:"login_max_attempts"`
	LoginLockoutDuration     time.Duration `json:"login_lockout_duration"`
	SessionMaxConcurrent     int           `json:"session_max_concurrent"`
	SessionCleanupInterval   time.Duration `json:"session_cleanup_interval"`
	RateLimitRequests        int           `json:"rate_limit_requests"`
	RateLimitWindow          time.Duration `json:"rate_limit_window"`
	IPWhitelist              []string      `json:"ip_whitelist"`
	IPBlacklist              []string      `json:"ip_blacklist"`
	RequireEmailVerification bool          `json:"require_email_verification"`
	AllowSelfRegistration    bool          `json:"allow_self_registration"`
	DefaultRole              string        `json:"default_role"`
	AuditLogRetentionDays    int           `json:"audit_log_retention_days"`
}

type CasdoorConfig struct {
	Endpoint     string `json:"endpoint"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"` // Hide from JSON
	Organization string `json:"organization"`
	Application  string `json:"application"`
	Certificate  string `json:"certificate"`
	JWTSecret    string `json:"-"` // Hide from JSON
}

func Load() (*Config, error) {
	// Load .env file if exists
	if err := godotenv.Load(); err != nil {
		// It's okay if .env doesn't exist
		fmt.Println("Warning: .env file not found, using environment variables")
	}

	config := &Config{
		Server: ServerConfig{
			Port:         getEnv("SERVER_PORT", "8080"),
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Environment:  getEnv("ENVIRONMENT", "development"),
			ReadTimeout:  getDurationEnv("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getDurationEnv("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getDurationEnv("SERVER_IDLE_TIMEOUT", 120*time.Second),
			CORS: CORSConfig{
				AllowedOrigins:   getStringSliceEnv("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
				AllowedMethods:   getStringSliceEnv("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
				AllowedHeaders:   getStringSliceEnv("CORS_ALLOWED_HEADERS", []string{"*"}),
				ExposedHeaders:   getStringSliceEnv("CORS_EXPOSED_HEADERS", []string{"*"}),
				AllowCredentials: getBoolEnv("CORS_ALLOW_CREDENTIALS", true),
				MaxAge:           getIntEnv("CORS_MAX_AGE", 86400),
			},
		},
		Database: DatabaseConfig{
			Host:         getEnv("DB_HOST", "localhost"),
			Port:         getIntEnv("DB_PORT", 5432),
			User:         getEnv("DB_USER", "auth_user"),
			Password:     getEnv("DB_PASSWORD", "auth_password"),
			Database:     getEnv("DB_NAME", "auth_db"),
			SSLMode:      getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns: getIntEnv("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns: getIntEnv("DB_MAX_IDLE_CONNS", 10),
			MaxLifetime:  getDurationEnv("DB_MAX_LIFETIME", 5*time.Minute),
			MaxIdleTime:  getDurationEnv("DB_MAX_IDLE_TIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:               getEnv("REDIS_HOST", "localhost"),
			Port:               getIntEnv("REDIS_PORT", 6379),
			Password:           getEnv("REDIS_PASSWORD", ""),
			Database:           getIntEnv("REDIS_DATABASE", 0),
			MaxRetries:         getIntEnv("REDIS_MAX_RETRIES", 3),
			MinRetryBackoff:    getDurationEnv("REDIS_MIN_RETRY_BACKOFF", 8*time.Millisecond),
			MaxRetryBackoff:    getDurationEnv("REDIS_MAX_RETRY_BACKOFF", 512*time.Millisecond),
			DialTimeout:        getDurationEnv("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:        getDurationEnv("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout:       getDurationEnv("REDIS_WRITE_TIMEOUT", 3*time.Second),
			PoolSize:           getIntEnv("REDIS_POOL_SIZE", 10),
			MinIdleConns:       getIntEnv("REDIS_MIN_IDLE_CONNS", 5),
			MaxConnAge:         getDurationEnv("REDIS_MAX_CONN_AGE", 30*time.Minute),
			PoolTimeout:        getDurationEnv("REDIS_POOL_TIMEOUT", 4*time.Second),
			IdleTimeout:        getDurationEnv("REDIS_IDLE_TIMEOUT", 5*time.Minute),
			IdleCheckFrequency: getDurationEnv("REDIS_IDLE_CHECK_FREQUENCY", time.Minute),
		},
		JWT: JWTConfig{
			SecretKey:            getEnv("JWT_SECRET_KEY", "your-super-secret-jwt-key-change-this-in-production"),
			AccessTokenExpiry:    getDurationEnv("JWT_ACCESS_TOKEN_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry:   getDurationEnv("JWT_REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),
			Issuer:               getEnv("JWT_ISSUER", "auth-service"),
			Audience:             getEnv("JWT_AUDIENCE", "exam-platform"),
			Algorithm:            getEnv("JWT_ALGORITHM", "HS256"),
			RefreshTokenRotation: getBoolEnv("JWT_REFRESH_TOKEN_ROTATION", true),
		},
		OAuth: OAuthConfig{
			AuthorizationCodeExpiry: getDurationEnv("OAUTH_AUTH_CODE_EXPIRY", 10*time.Minute),
			AccessTokenExpiry:       getDurationEnv("OAUTH_ACCESS_TOKEN_EXPIRY", time.Hour),
			RefreshTokenExpiry:      getDurationEnv("OAUTH_REFRESH_TOKEN_EXPIRY", 24*time.Hour),
			Scopes:                  getStringSliceEnv("OAUTH_SCOPES", []string{"openid", "profile", "email"}),
			PKCERequired:            getBoolEnv("OAUTH_PKCE_REQUIRED", true),
		},
		Social: SocialConfig{
			Google: GoogleConfig{
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/api/auth/callback/google"),
				Scopes:       getStringSliceEnv("GOOGLE_SCOPES", []string{"openid", "profile", "email"}),
				AuthURL:      getEnv("GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth"),
				TokenURL:     getEnv("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token"),
				UserInfoURL:  getEnv("GOOGLE_USERINFO_URL", "https://www.googleapis.com/oauth2/v2/userinfo"),
			},
			Microsoft: MicrosoftConfig{
				ClientID:     getEnv("MICROSOFT_CLIENT_ID", ""),
				ClientSecret: getEnv("MICROSOFT_CLIENT_SECRET", ""),
				TenantID:     getEnv("MICROSOFT_TENANT_ID", "common"),
				RedirectURL:  getEnv("MICROSOFT_REDIRECT_URL", "http://localhost:8080/api/auth/callback/microsoft"),
				Scopes:       getStringSliceEnv("MICROSOFT_SCOPES", []string{"openid", "profile", "email", "User.Read"}),
				AuthURL:      getEnv("MICROSOFT_AUTH_URL", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
				TokenURL:     getEnv("MICROSOFT_TOKEN_URL", "https://login.microsoftonline.com/common/oauth2/v2.0/token"),
				UserInfoURL:  getEnv("MICROSOFT_USERINFO_URL", "https://graph.microsoft.com/v1.0/me"),
			},
		},
		MFA: MFAConfig{
			Issuer:               getEnv("MFA_ISSUER", "SAP Trust"),
			TOTPWindowSize:       getIntEnv("MFA_TOTP_WINDOW_SIZE", 1),
			BackupCodesCount:     getIntEnv("MFA_BACKUP_CODES_COUNT", 10),
			BackupCodeLength:     getIntEnv("MFA_BACKUP_CODE_LENGTH", 8),
			QRCodeSize:           getIntEnv("MFA_QR_CODE_SIZE", 256),
			SetupTokenExpiry:     getDurationEnv("MFA_SETUP_TOKEN_EXPIRY", 10*time.Minute),
			ChallengeTokenExpiry: getDurationEnv("MFA_CHALLENGE_TOKEN_EXPIRY", 5*time.Minute),
			RequiredForRoles:     getStringSliceEnv("MFA_REQUIRED_FOR_ROLES", []string{"admin", "proctor"}),
		},
		Email: EmailConfig{
			SMTPHost:            getEnv("SMTP_HOST", "localhost"),
			SMTPPort:            getIntEnv("SMTP_PORT", 587),
			SMTPUsername:        getEnv("SMTP_USERNAME", ""),
			SMTPPassword:        getEnv("SMTP_PASSWORD", ""),
			FromEmail:           getEnv("FROM_EMAIL", "noreply@examplatform.com"),
			FromName:            getEnv("FROM_NAME", "Exam Platform"),
			UseTLS:              getBoolEnv("SMTP_USE_TLS", true),
			VerificationExpiry:  getDurationEnv("EMAIL_VERIFICATION_EXPIRY", 24*time.Hour),
			PasswordResetExpiry: getDurationEnv("PASSWORD_RESET_EXPIRY", time.Hour),
			MaxRetries:          getIntEnv("EMAIL_MAX_RETRIES", 3),
			RetryDelay:          getDurationEnv("EMAIL_RETRY_DELAY", 30*time.Second),
		},
		Security: SecurityConfig{
			PasswordMinLength:        getIntEnv("PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUppercase: getBoolEnv("PASSWORD_REQUIRE_UPPERCASE", true),
			PasswordRequireLowercase: getBoolEnv("PASSWORD_REQUIRE_LOWERCASE", true),
			PasswordRequireNumbers:   getBoolEnv("PASSWORD_REQUIRE_NUMBERS", true),
			PasswordRequireSpecial:   getBoolEnv("PASSWORD_REQUIRE_SPECIAL", true),
			BcryptCost:               getIntEnv("BCRYPT_COST", 12),
			LoginMaxAttempts:         getIntEnv("LOGIN_MAX_ATTEMPTS", 5),
			LoginLockoutDuration:     getDurationEnv("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			SessionMaxConcurrent:     getIntEnv("SESSION_MAX_CONCURRENT", 3),
			SessionCleanupInterval:   getDurationEnv("SESSION_CLEANUP_INTERVAL", time.Hour),
			RateLimitRequests:        getIntEnv("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:          getDurationEnv("RATE_LIMIT_WINDOW", time.Hour),
			IPWhitelist:              getStringSliceEnv("IP_WHITELIST", []string{}),
			IPBlacklist:              getStringSliceEnv("IP_BLACKLIST", []string{}),
			RequireEmailVerification: getBoolEnv("REQUIRE_EMAIL_VERIFICATION", true),
			AllowSelfRegistration:    getBoolEnv("ALLOW_SELF_REGISTRATION", true),
			DefaultRole:              getEnv("DEFAULT_ROLE", "student"),
			AuditLogRetentionDays:    getIntEnv("AUDIT_LOG_RETENTION_DAYS", 90),
		},
		Casdoor: CasdoorConfig{
			Endpoint:     getEnv("CASDOOR_ENDPOINT", "http://localhost:8000"),
			ClientID:     getEnv("CASDOOR_CLIENT_ID", ""),
			ClientSecret: getEnv("CASDOOR_CLIENT_SECRET", ""),
			Organization: getEnv("CASDOOR_ORGANIZATION", "built-in"),
			Application:  getEnv("CASDOOR_APPLICATION", "exam-platform"),
			Certificate:  getEnv("CASDOOR_CERTIFICATE", ""),
			JWTSecret:    getEnv("CASDOOR_JWT_SECRET", ""),
		},
	}

	// Validate required configurations
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

func (c *Config) Validate() error {
	// Validate JWT configuration
	if c.JWT.SecretKey == "" || c.JWT.SecretKey == "your-super-secret-jwt-key-change-this-in-production" {
		return fmt.Errorf("JWT_SECRET_KEY must be set and should not use default value")
	}

	// Validate database configuration
	if c.Database.Host == "" {
		return fmt.Errorf("DB_HOST must be set")
	}
	if c.Database.User == "" {
		return fmt.Errorf("DB_USER must be set")
	}
	if c.Database.Password == "" {
		return fmt.Errorf("DB_PASSWORD must be set")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("DB_NAME must be set")
	}

	// Validate Redis configuration
	if c.Redis.Host == "" {
		return fmt.Errorf("REDIS_HOST must be set")
	}

	// Validate Social Login configs if enabled
	if c.Social.Google.ClientID != "" && c.Social.Google.ClientSecret == "" {
		return fmt.Errorf("GOOGLE_CLIENT_SECRET must be set when GOOGLE_CLIENT_ID is provided")
	}
	if c.Social.Microsoft.ClientID != "" && c.Social.Microsoft.ClientSecret == "" {
		return fmt.Errorf("MICROSOFT_CLIENT_SECRET must be set when MICROSOFT_CLIENT_ID is provided")
	}

	// Validate security settings
	if c.Security.BcryptCost < 10 || c.Security.BcryptCost > 15 {
		return fmt.Errorf("BCRYPT_COST must be between 10 and 15")
	}

	return nil
}

func (c *Config) GetDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
