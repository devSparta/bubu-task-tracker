package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
)

type fakePasswordHasher struct {
	called   bool
	password string
	hash     string
	err      error
}

type fakeUserRepository struct {
	called      bool
	params      CreateUserParams
	createdUser user.User
	err         error
}

func (h *fakePasswordHasher) Hash(password string) (string, error) {
	h.called = true
	h.password = password

	return h.hash, h.err
}

func (r *fakeUserRepository) Create(
	ctx context.Context,
	params CreateUserParams,
) (user.User, error) {
	r.called = true
	r.params = params

	return r.createdUser, r.err
}

func TestNormalizeRegisterInput(t *testing.T) {
	input := RegisterInput{
		Email:       " TeSting@mail.ru ",
		DisplayName: " user_test  ",
		Password:    " 123456h78df9gf ",
	}

	want := RegisterInput{
		Email:       "testing@mail.ru",
		DisplayName: "user_test",
		Password:    " 123456h78df9gf ",
	}

	got := normalizeRegisterInput(input)

	if got != want {
		t.Fatalf("normalizeRegisterInput() = %#v, want %#v", got, want)
	}
}

func TestValidateRegisterInput(t *testing.T) {
	tests := []struct {
		name      string
		input     RegisterInput
		wantField string
		wantErr   bool
	}{
		{
			name: "valid input",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    "123456h78df9gfhd",
			},
			wantErr: false,
		},
		{
			name: "invalid email",
			input: RegisterInput{
				Email:       "not-an-email",
				DisplayName: "user_test",
				Password:    "123456h78df9gfhd",
			},
			wantField: "email",
			wantErr:   true,
		},
		{
			name: "empty display name",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "",
				Password:    "123456h78df9gfhd",
			},
			wantField: "display_name",
			wantErr:   true,
		},
		{
			name: "short password",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    "12345",
			},
			wantField: "password",
			wantErr:   true,
		},
		{
			name: "password 14",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    strings.Repeat("a", 14),
			},
			wantField: "password",
			wantErr:   true,
		},
		{
			name: "password 15",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    strings.Repeat("a", 15),
			},
			wantErr: false,
		},
		{
			name: "password 128",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    strings.Repeat("a", 128),
			},
			wantErr: false,
		},
		{
			name: "password 129",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    strings.Repeat("a", 129),
			},
			wantField: "password",
			wantErr:   true,
		},
		{
			name: "password unicode",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: "user_test",
				Password:    strings.Repeat("🔒", 15),
			},
			wantErr: false,
		},
		{
			name: "display_name 100",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: strings.Repeat("a", 100),
				Password:    "123456h78df9gfhd",
			},
			wantErr: false,
		},
		{
			name: "display_name 101",
			input: RegisterInput{
				Email:       "testing@mail.ru",
				DisplayName: strings.Repeat("a", 101),
				Password:    "123456h78df9gfhd",
			},
			wantField: "display_name",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRegisterInput(tc.input)

			if !tc.wantErr {
				if err != nil {
					t.Fatalf(
						"validateRegisterInput() error = %v, want nil",
						err,
					)
				}

				return
			}

			if err == nil {
				t.Fatalf(
					"validateRegisterInput() error = nil, want ValidationError for field %q",
					tc.wantField,
				)
			}

			var validationErr *ValidationError

			if !errors.As(err, &validationErr) {
				t.Fatalf(
					"validateRegisterInput() error type = %T, want *ValidationError",
					err,
				)
			}

			if validationErr.Field != tc.wantField {
				t.Fatalf(
					"ValidationError.Field = %q, want %q",
					validationErr.Field,
					tc.wantField,
				)
			}
		})
	}
}

func TestServiceRegisterValidationFailureDoesNotCallDependencies(t *testing.T) {
	input := RegisterInput{
		Email:       "testing@mail.ru",
		DisplayName: "user_test",
		Password:    "12345",
	}

	hasher := &fakePasswordHasher{
		hash: "hashed",
	}

	repo := &fakeUserRepository{}

	service := NewService(repo, hasher)

	_, err := service.Register(context.Background(), input)

	var validationErr *ValidationError

	if !errors.As(err, &validationErr) {
		t.Fatal("Need validation error")
	}

	if validationErr.Field != "password" {
		t.Fatalf(
			"ValidationError.Field = %q, want %q",
			validationErr.Field,
			"password",
		)
	}

	if hasher.called {
		t.Fatal("hasher was called for invalid input")
	}

	if repo.called {
		t.Fatal("repository was called for invalid input")
	}
}

func TestServiceRegisterSuccess(t *testing.T) {
	input := RegisterInput{
		Email:       " TeSting@Mail.Ru ",
		DisplayName: " User Test ",
		Password:    "  correct-password  ",
	}

	hasher := &fakePasswordHasher{
		hash: "hashed",
		err:  nil,
	}

	wantUser := user.User{
		Email:       "testing@mail.ru",
		DisplayName: "User Test",
	}

	repo := &fakeUserRepository{
		createdUser: wantUser,
	}

	service := NewService(repo, hasher)

	createdUser, err := service.Register(context.Background(), input)

	if err != nil {
		t.Fatalf("Register() error = %v, want nil", err)
	}

	if !hasher.called {
		t.Fatal("hasher was not called")
	}

	if !repo.called {
		t.Fatal("repository was not called")
	}

	if hasher.password != input.Password {
		t.Fatal("invalid password in hasher")
	}

	wantParams := CreateUserParams{
		Email:        "testing@mail.ru",
		DisplayName:  "User Test",
		PasswordHash: "hashed",
	}

	if repo.params != wantParams {
		t.Fatalf(
			"repository params = %#v, want %#v",
			repo.params,
			wantParams,
		)
	}

	if createdUser != wantUser {
		t.Fatalf(
			"Register() user = %#v, want %#v",
			createdUser,
			wantUser,
		)
	}
}

func TestServiceRegisterHasherFailureStopsBeforeRepository(t *testing.T) {
	hashErr := errors.New("hash failed")

	hasher := &fakePasswordHasher{
		err:  hashErr,
	}

	repo := &fakeUserRepository{}

	service := NewService(repo, hasher)

	input := RegisterInput{
		Email:       " TeSting@Mail.Ru ",
		DisplayName: " User Test ",
		Password:    "  correct-password  ",
	}

	_, err := service.Register(context.Background(), input)

	if err == nil {
		t.Fatal("Register() error = nil, want hash error")
	}

	if !errors.Is(err, hashErr) {
		t.Fatalf("Register() error = %v, want %v", err, hashErr)
	}

	if !hasher.called {
		t.Fatal("hasher was not called")
	}

	if hasher.password != input.Password {
		t.Fatalf(
			"hasher password = %q, want %q",
			hasher.password,
			input.Password,
		)
	}

	if repo.called {
		t.Fatal("repository was called")
	}
}

func TestServiceRegisterPreservesEmailAlreadyExistsError(t *testing.T) {
	hasher := &fakePasswordHasher{
		hash: "hashed",
		err:  nil,
	}

	repo := &fakeUserRepository{
		err: ErrEmailAlreadyExists,
	}

	input := RegisterInput{
		Email:       " TeSting@Mail.Ru ",
		DisplayName: " User Test ",
		Password:    "  correct-password  ",
	}

	service := NewService(repo, hasher)

	_, err := service.Register(context.Background(), input)

	if err == nil {
		t.Fatal("Register() error = nil, want email already exists")
	}

	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("Register() error = %v, want ErrEmailAlreadyExists", err)
	}

	if !hasher.called {
		t.Fatal("hasher was not called")
	}

	if !repo.called {
		t.Fatal("repository was not called")
	}
}