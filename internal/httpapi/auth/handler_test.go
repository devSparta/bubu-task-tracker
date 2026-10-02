package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authapp "github.com/devSparta/bubu-task-tracker/internal/application/auth"
	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
	"github.com/google/uuid"
)

type fakeRegistrationService struct {
	called      bool
	input       authapp.RegisterInput
	createdUser user.User
	err         error
}

func (s *fakeRegistrationService) Register(_ context.Context, input authapp.RegisterInput) (user.User, error) {
	s.called = true
	s.input = input

	return s.createdUser, s.err
}

func TestHandlerRegisterRejectsUnsupportedMediaType(t *testing.T) {
	service := &fakeRegistrationService{}

	handler := NewHandler(service)

	reader := strings.NewReader(`{}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", reader)

	rec := httptest.NewRecorder()

	req.Header.Set("Content-Type", "text/plain")

	handler.Register(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatal("expected HTTP status 415")
	}

	if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatal("expected Content-Type \"application/problem+json; charset=utf-8\"")
	}

	var problem struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if problem.Status != http.StatusUnsupportedMediaType {
		t.Fatalf(
			"problem status = %d, want %d",
			problem.Status,
			http.StatusUnsupportedMediaType,
		)
	}

	if problem.Code != "UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf(
			"problem code = %q, want %q",
			problem.Code,
			"UNSUPPORTED_MEDIA_TYPE",
		)
	}

	if service.called {
		t.Fatal("registration service was called for unsupported media type")
	}
}

func TestHandlerRegisterRejectsInvalidRequestBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty body",
			body: "",
		},
		{
			name: "malformed JSON",
			body: `{"email":"`,
		},
		{
			name: "unknown field",
			body: `{
				"email":"user@example.com",
				"display_name":"User",
				"password":"correct-password",
				"role":"admin"
			}`,
		},
		{
			name: "multiple JSON values",
			body: `{}` + `{}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeRegistrationService{}

			handler := NewHandler(service)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(tc.body))

			rec := httptest.NewRecorder()

			req.Header.Set("Content-Type", "application/json")

			handler.Register(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatal("expected HTTP status 400")
			}

			if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
				t.Fatal(`expected Content-Type "application/problem+json; charset=utf-8"`)
			}

			var problem struct {
				Status int    `json:"status"`
				Code   string `json:"code"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem response: %v", err)
			}

			if problem.Status != http.StatusBadRequest {
				t.Fatalf(
					"problem status = %d, want %d",
					problem.Status,
					http.StatusBadRequest,
				)
			}

			if problem.Code != "INVALID_REQUEST_BODY" {
				t.Fatalf(
					"problem code = %q, want %q",
					problem.Code,
					"INVALID_REQUEST_BODY",
				)
			}

			if service.called {
				t.Fatal("registration service was called for invalid JSON body")
			}
		})
	}
}

func TestHandlerRegisterRejectsTooLargeBody(t *testing.T) {
	service := &fakeRegistrationService{}

	handler := NewHandler(service)

	tooLargeData := `{"email":"` +
		strings.Repeat("a", (64<<10)+1) +
		`"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(tooLargeData))

	rec := httptest.NewRecorder()
	req.Header.Set("Content-Type", "application/json")

	handler.Register(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusRequestEntityTooLarge,
		)
	}

	if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatal(`expected Content-Type "application/problem+json; charset=utf-8"`)
	}

	var problem struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if problem.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf(
			"problem status = %d, want %d",
			problem.Status,
			http.StatusRequestEntityTooLarge,
		)
	}

	if problem.Code != "REQUEST_BODY_TOO_LARGE" {
		t.Fatalf(
			"problem code = %q, want %q",
			problem.Code,
			"REQUEST_BODY_TOO_LARGE",
		)
	}

	if service.called {
		t.Fatal("registration service was called for too large body")
	}
}

func TestHandlerRegisterMapsValidationErrorToUnprocessableEntity(t *testing.T) {
	validationErr := &authapp.ValidationError{
		Field:  "email",
		Reason: "must not be empty",
	}

	service := &fakeRegistrationService{
		err: validationErr,
	}

	handler := NewHandler(service)

	input := `{
		"email": "",
		"display_name": "User",
		"password": "correct-password"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(input))

	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusUnprocessableEntity,
		)
	}

	if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusUnprocessableEntity,
		)
	}

	if !service.called {
		t.Fatal("registration service was not called for invalid JSON body")
	}

	wantInput := authapp.RegisterInput{
		Email:       "",
		DisplayName: "User",
		Password:    "correct-password",
	}

	if service.input != wantInput {
		t.Fatalf(
			"service input = %#v, want %#v",
			service.input,
			wantInput,
		)
	}

	var problem struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if problem.Status != http.StatusUnprocessableEntity {
		t.Fatalf(
			"problem status = %d, want %d",
			problem.Status,
			http.StatusUnprocessableEntity,
		)
	}

	if problem.Code != "VALIDATION_FAILED" {
		t.Fatalf("problem code = %q, want %q", problem.Code, "VALIDATION_FAILED")
	}

	if problem.Detail != "email: must not be empty" {
		t.Fatalf(
			"problem.Detail = %q, want %q",
			problem.Detail,
			"email: must not be empty",
		)
	}
}

func TestHandlerRegisterMapsEmailAlreadyExistsErrorToConflict(t *testing.T) {
	service := &fakeRegistrationService{
		err: fmt.Errorf(
			"create user: %w",
			authapp.ErrEmailAlreadyExists,
		),
	}

	handler := NewHandler(service)

	body := `{
		"email": "user@example.com",
		"display_name": "User",
		"password": "correct-password"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/register",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusConflict,
		)
	}

	if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatalf(
			"response Content-Type = %q, want %q",
			resp.Header.Get("Content-Type"),
			"application/problem+json; charset=utf-8",
		)
	}

	if !service.called {
		t.Fatal("registration service was not called")
	}

	wantInput := authapp.RegisterInput{
		Email:       "user@example.com",
		DisplayName: "User",
		Password:    "correct-password",
	}

	if service.input != wantInput {
		t.Fatalf(
			"service input = %#v, want %#v",
			service.input,
			wantInput,
		)
	}

	var problem struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if problem.Status != http.StatusConflict {
		t.Fatalf(
			"problem status = %d, want %d",
			problem.Status,
			http.StatusConflict,
		)
	}

	if problem.Code != "EMAIL_ALREADY_REGISTERED" {
		t.Fatalf(
			"problem code = %q, want %q",
			problem.Code,
			"EMAIL_ALREADY_REGISTERED",
		)
	}
}

func TestHandlerRegisterMapsUnexpectedErrorToInternalServerError(t *testing.T) {
	service := &fakeRegistrationService{
		err: errors.New("database connection lost"),
	}

	handler := NewHandler(service)

	body := `{
		"email":       "user@example.com",
		"display_name": "User",
		"password":    "correct-password"
	}`

	wantInput := authapp.RegisterInput{
		Email:       "user@example.com",
		DisplayName: "User",
		Password:    "correct-password",
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/register",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler.Register(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if service.input != wantInput {
		t.Fatalf(
			"service input = %#v, want %#v",
			service.input,
			wantInput,
		)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("response status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	if resp.Header.Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatalf(
			"response Content-Type = %q, want %q",
			resp.Header.Get("Content-Type"),
			"application/problem+json; charset=utf-8",
		)
	}

	if !service.called {
		t.Fatal("registration service was not called")
	}

	var problem struct {
		Status int    `json:"status"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if problem.Status != http.StatusInternalServerError {
		t.Fatalf("problem status = %d, want %d", problem.Status, http.StatusInternalServerError)
	}

	if problem.Code != "INTERNAL_ERROR" {
		t.Fatalf("problem.Code = %q, want %q", problem.Code, "INTERNAL_ERROR")
	}

	if strings.Contains(problem.Detail, "database connection lost") {
		t.Fatalf("internal error leaked in problem detail: %q", problem.Detail)
	}
}

func TestHandlerRegisterReturnsCreatedUser(t *testing.T) {
	createdAt := time.Date(2026, time.October, 10, 23, 0, 0, 0, time.UTC)

	createdUser := user.User{
		ID:              uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Email:           "user@example.com",
		DisplayName:     "User",
		EmailVerifiedAt: nil,
		CreatedAt:       createdAt,
	}

	service := &fakeRegistrationService{
		createdUser: createdUser,
	}

	handler := NewHandler(service)

	body := `{
		"email":       "user@example.com",
		"display_name": "User",
		"password":    "correct-password"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))

	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusCreated,
		)
	}

	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf(
			"response Content-Type = %q, want %q",
			resp.Header.Get("Content-Type"),
			"application/json; charset=utf-8",
		)
	}

	if !service.called {
		t.Fatal("registration service was not called")
	}

	var respBody struct {
		ID              string    `json:"id"`
		Email           string    `json:"email"`
		DisplayName     string    `json:"display_name"`
		EmailVerified *bool     `json:"email_verified"`
		CreatedAt       time.Time `json:"created_at"`
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&respBody); err != nil {
		t.Fatalf("decode problem response: %v", err)
	}

	if respBody.ID != createdUser.ID.String() {
		t.Fatalf(
			"response ID = %q, want %q",
			respBody.ID,
			createdUser.ID.String(),
		)
	}

	if respBody.Email != createdUser.Email {
		t.Fatalf(
			"response email = %q, want %q",
			respBody.Email,
			createdUser.Email,
		)
	}

	if respBody.DisplayName != createdUser.DisplayName {
		t.Fatalf(
			"response display name = %q, want %q",
			respBody.DisplayName,
			createdUser.DisplayName,
		)
	}

	wantEmailVerified := createdUser.EmailVerifiedAt != nil

	if respBody.EmailVerified == nil {
		t.Fatal(`registration response does not contain "email_verified"`)
	}

	if *respBody.EmailVerified != wantEmailVerified {
		t.Fatalf(
			"response email_verified = %t, want %t",
			*respBody.EmailVerified,
			wantEmailVerified,
		)
	}

	if !respBody.CreatedAt.Equal(createdUser.CreatedAt) {
		t.Fatalf(
			"response created_at = %s, want %s",
			respBody.CreatedAt,
			createdUser.CreatedAt,
		)
	}

	wantInput := authapp.RegisterInput{
		Email:       "user@example.com",
		DisplayName: "User",
		Password:    "correct-password",
	}

	if service.input != wantInput {
		t.Fatalf(
			"service input = %#v, want %#v",
			service.input,
			wantInput,
		)
	}
}
