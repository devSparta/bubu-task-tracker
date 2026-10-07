package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
)

const (
	sessionIdleTimeout     = 12 * time.Hour
	sessionAbsoluteTimeout = 30 * 24 * time.Hour
)

type RegisterInput struct {
	Email       string
	DisplayName string
	Password    string
}

type RegisterResult struct {
	User             user.User
	SessionToken     string
	CSRFToken        string
	SessionExpiresAt time.Time
}

type CreateUserParams struct {
	Email        string
	DisplayName  string
	PasswordHash string
}

type CreateSessionParams struct {
	TokenHash         []byte
	CSRFTokenHash     []byte
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
}

type CreateUserWithSessionParams struct {
	User    CreateUserParams
	Session CreateSessionParams
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type RegistrationRepository interface {
	CreateUserWithSession(ctx context.Context, params CreateUserWithSessionParams) (user.User, error)
}

type SessionTokenGenerator interface {
	Generate() (token string, hash []byte, err error)
}

type Clock interface {
	Now() time.Time
}

type Service struct {
	registrations RegistrationRepository
	hasher        PasswordHasher
	generator     SessionTokenGenerator
	clock         Clock
}

// Конструктор Service
func NewService(registrations RegistrationRepository, hasher PasswordHasher, generator SessionTokenGenerator, clock Clock) *Service {
	return &Service{
		registrations: registrations,
		hasher:        hasher,
		generator:     generator,
		clock:         clock,
	}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (RegisterResult, error) {
	normalized := normalizeRegisterInput(input)

	err := validateRegisterInput(normalized)
	if err != nil {
		return RegisterResult{}, err
	}

	passwordHash, err := s.hasher.Hash(normalized.Password)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("hash password: %w", err)
	}

	sessionToken, sessionHash, err := s.generator.Generate()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate session token: %w", err)
	}

	csrfToken, csrfHash, err := s.generator.Generate()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate CSRF token: %w", err)
	}

	userParams := CreateUserParams{
		Email:        normalized.Email,
		DisplayName:  normalized.DisplayName,
		PasswordHash: passwordHash,
	}

	now := s.clock.Now().UTC()

	sessionParams := CreateSessionParams{
		TokenHash:         sessionHash,
		CSRFTokenHash:     csrfHash,
		CreatedAt:         now,
		LastSeenAt:        now,
		ExpiresAt:         now.Add(sessionIdleTimeout),
		AbsoluteExpiresAt: now.Add(sessionAbsoluteTimeout),
	}

	params := CreateUserWithSessionParams{
		User:    userParams,
		Session: sessionParams,
	}

	createdUser, err := s.registrations.CreateUserWithSession(ctx, params)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("create user with session: %w", err)
	}

	result := RegisterResult{
		User:             createdUser,
		SessionToken:     sessionToken,
		CSRFToken:        csrfToken,
		SessionExpiresAt: sessionParams.AbsoluteExpiresAt,
	}

	return result, nil
}

// Нормализует поля в структуре input, возвращает нормализованную структуру RegisterInput
func normalizeRegisterInput(input RegisterInput) RegisterInput {
	return RegisterInput{
		Email:       strings.ToLower(strings.TrimSpace(input.Email)),
		DisplayName: strings.TrimSpace(input.DisplayName),
		Password:    input.Password,
	}
}

// Валидирует поля в структуре input, возвращает ошибку при наличии, иначе nil
func validateRegisterInput(input RegisterInput) error {
	//Email valid
	if input.Email == "" || len(input.Email) > 254 {
		return &ValidationError{
			Field:  "email",
			Reason: "incorrect email address",
		}
	}

	addr, err := mail.ParseAddress(input.Email)
	if err != nil {
		return &ValidationError{
			Field:  "email",
			Reason: "must be a valid email address",
		}
	}

	if addr.Address != input.Email {
		return &ValidationError{
			Field:  "email",
			Reason: "incorrect email address",
		}
	}

	//DisplayName valid
	if input.DisplayName == "" || utf8.RuneCountInString(input.DisplayName) > 100 {
		return &ValidationError{
			Field:  "display_name",
			Reason: "incorrect display name",
		}
	}

	//Password valid
	passwordLength := utf8.RuneCountInString(input.Password)

	if input.Password == "" || passwordLength < 15 {
		return &ValidationError{
			Field:  "password",
			Reason: "password must be at least 15 characters",
		}
	}

	if passwordLength > 128 {
		return &ValidationError{
			Field:  "password",
			Reason: "password must be at most 128 characters",
		}
	}

	return nil
}
