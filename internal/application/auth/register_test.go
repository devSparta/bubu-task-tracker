package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
	params      CreateUserWithSessionParams
	createdUser user.User
	err         error
}

type generateResult struct {
	token string
	hash  []byte
	err   error
}

type fakeGenerator struct {
	results []generateResult
	calls   int
}

func (g *fakeGenerator) Generate() (string, []byte, error) {
	res := g.results[g.calls]
	g.calls++

	return res.token, res.hash, res.err
}

type fakeClock struct {
	now time.Time
}

func (s *fakeClock) Now() time.Time {
	return s.now
}

func (h *fakePasswordHasher) Hash(password string) (string, error) {
	h.called = true
	h.password = password

	return h.hash, h.err
}

func (r *fakeUserRepository) CreateUserWithSession(
	ctx context.Context,
	params CreateUserWithSessionParams,
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

	generator := &fakeGenerator{}

	clock := &fakeClock{}

	service := NewService(repo, hasher, generator, clock)

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

	if generator.calls != 0 {
		t.Fatal("generator was called")
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

	wantSessionToken := "session-token"
	wantSessionHash := bytes.Repeat([]byte{1}, 32)

	wantCSRFToken := "csrf-token"
	wantCSRFHash := bytes.Repeat([]byte{2}, 32)

	generator := &fakeGenerator{
		results: []generateResult{
			{
				token: wantSessionToken,
				hash:  wantSessionHash,
			},
			{
				token: wantCSRFToken,
				hash:  wantCSRFHash,
			},
		},
	}

	wantNow := time.Date(2026, time.October, 10, 10, 0, 0, 0, time.UTC)

	clock := &fakeClock{
		now: wantNow,
	}

	service := NewService(repo, hasher, generator, clock)

	registerResult, err := service.Register(context.Background(), input)

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

	if repo.params.User != wantParams {
		t.Fatalf(
			"repository params = %#v, want %#v",
			repo.params.User,
			wantParams,
		)
	}

	if registerResult.User != wantUser {
		t.Fatalf(
			"Register() user = %#v, want %#v",
			registerResult.User,
			wantUser,
		)
	}

	if generator.calls != 2 {
		t.Fatalf("generator called = %d, want 2", generator.calls)
	}

	if registerResult.SessionToken != wantSessionToken {
		t.Fatalf("invalid session token = %v, want %v", registerResult.SessionToken, wantSessionToken)
	}

	if registerResult.CSRFToken != wantCSRFToken {
		t.Fatalf("invalid csrf token = %v, want %v", registerResult.CSRFToken, wantCSRFToken)
	}

	if !bytes.Equal(repo.params.Session.TokenHash, wantSessionHash) {
		t.Fatalf("invalid session hash = %v, want %v", repo.params.Session.TokenHash, wantSessionHash)
	}

	if !bytes.Equal(repo.params.Session.CSRFTokenHash, wantCSRFHash) {
		t.Fatalf("invalid csrf hash = %v, want %v", repo.params.Session.CSRFTokenHash, wantCSRFHash)
	}

	if !repo.params.Session.CreatedAt.Equal(wantNow) {
		t.Fatalf(
			"session CreatedAt = %v, want %v",
			repo.params.Session.CreatedAt,
			wantNow,
		)
	}

	if !repo.params.Session.LastSeenAt.Equal(wantNow) {
		t.Fatalf(
			"session LastSeenAt = %v, want %v",
			repo.params.Session.LastSeenAt,
			wantNow,
		)
	}

	if !repo.params.Session.ExpiresAt.Equal(wantNow.Add(sessionIdleTimeout)) {
		t.Fatalf(
			"session ExpiresAt = %v, want %v",
			repo.params.Session.ExpiresAt,
			wantNow.Add(sessionIdleTimeout),
		)
	}

	if !repo.params.Session.AbsoluteExpiresAt.Equal(wantNow.Add(sessionAbsoluteTimeout)) {
		t.Fatalf(
			"session AbsoluteExpiresAt = %v, want %v",
			repo.params.Session.AbsoluteExpiresAt,
			wantNow.Add(sessionAbsoluteTimeout),
		)
	}

	if !registerResult.SessionExpiresAt.Equal(wantNow.Add(sessionAbsoluteTimeout)) {
		t.Fatalf(
			"session SessionExpiresAt = %v, want %v",
			registerResult.SessionExpiresAt,
			wantNow.Add(sessionAbsoluteTimeout),
		)
	}
}

func TestServiceRegisterHasherFailureStopsBeforeRepository(t *testing.T) {
	hashErr := errors.New("hash failed")

	hasher := &fakePasswordHasher{
		err: hashErr,
	}

	repo := &fakeUserRepository{}

	generator := &fakeGenerator{}

	clock := &fakeClock{}

	service := NewService(repo, hasher, generator, clock)

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

	if generator.calls != 0 {
		t.Fatal("generator was called after hasher failure")
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

	wantSessionToken := "session-token"
	wantSessionHash := bytes.Repeat([]byte{1}, 32)

	wantCSRFToken := "csrf-token"
	wantCSRFHash := bytes.Repeat([]byte{2}, 32)

	generator := &fakeGenerator{
		results: []generateResult{
			{
				token: wantSessionToken,
				hash:  wantSessionHash,
			},
			{
				token: wantCSRFToken,
				hash:  wantCSRFHash,
			},
		},
	}

	clock := &fakeClock{}

	service := NewService(repo, hasher, generator, clock)

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

	if generator.calls != 2 {
		t.Fatalf("generator called = %d, want 2", generator.calls)
	}
}
