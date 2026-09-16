package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
)

type RegisterInput struct {
	Email       string
	DisplayName string
	Password    string
}

type CreateUserParams struct {
	Email        string
	DisplayName  string
	PasswordHash string
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type UserRepository interface {
	Create(ctx context.Context, params CreateUserParams) (user.User, error)
}

type Service struct {
	users  UserRepository
	hasher PasswordHasher
}

// Конструктор Service
func NewService(users UserRepository, hasher PasswordHasher) *Service {
	return &Service{
		users:  users,
		hasher: hasher,
	}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (user.User, error) {
	normalized := normalizeRegisterInput(input)

	err := validateRegisterInput(normalized)
	if err != nil {
		return user.User{}, err
	}

	passwordHash, err := s.hasher.Hash(normalized.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("hash password: %w", err)
	}

	params := CreateUserParams{
		Email:        normalized.Email,
		DisplayName:  normalized.DisplayName,
		PasswordHash: passwordHash,
	}

	createdUser, err := s.users.Create(ctx, params)
	if err != nil {
		return user.User{}, fmt.Errorf("create user: %w", err)
	}

	return createdUser, nil
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
