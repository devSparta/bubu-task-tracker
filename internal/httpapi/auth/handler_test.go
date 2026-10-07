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
	called bool
	input  authapp.RegisterInput
	result authapp.RegisterResult
	err    error
}

func (s *fakeRegistrationService) Register(_ context.Context, input authapp.RegisterInput) (authapp.RegisterResult, error) {
	s.called = true
	s.input = input

	return s.result, s.err
}

func TestHandlerRegisterRejectsUnsupportedMediaType(t *testing.T) {
	service := &fakeRegistrationService{}

	sessionCookieConfig := SessionCookieConfig{}

	handler := NewHandler(service, sessionCookieConfig)

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

			sessionCookieConfig := SessionCookieConfig{}

			handler := NewHandler(service, sessionCookieConfig)

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

	sessionCookieConfig := SessionCookieConfig{}

	handler := NewHandler(service, sessionCookieConfig)

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

	sessionCookieConfig := SessionCookieConfig{}

	handler := NewHandler(service, sessionCookieConfig)

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

	sessionCookieConfig := SessionCookieConfig{}

	handler := NewHandler(service, sessionCookieConfig)

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

	sessionCookieConfig := SessionCookieConfig{}

	handler := NewHandler(service, sessionCookieConfig)

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

func TestHandlerRegisterReturnsCreatedUserAndSetsSession(t *testing.T) {
	createdAt := time.Date(2026, time.October, 10, 23, 0, 0, 0, time.UTC)

	createdUser := user.User{
		ID:              uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Email:           "user@example.com",
		DisplayName:     "User",
		EmailVerifiedAt: nil,
		CreatedAt:       createdAt,
	}

	registerResult := authapp.RegisterResult{
		User:             createdUser,
		SessionToken:     "session-token",
		CSRFToken:        "csrf-token",
		SessionExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}

	service := &fakeRegistrationService{
		result: registerResult,
	}

	sessionCookieConfig := SessionCookieConfig{
		Name:   "session",
		Secure: false,
	}

	handler := NewHandler(service, sessionCookieConfig)

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

	//Проверка заголовков
	if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf(
			"response Content-Type = %q, want %q",
			resp.Header.Get("Content-Type"),
			"application/json; charset=utf-8",
		)
	}

	if resp.Header.Get("X-CSRF-Token") != registerResult.CSRFToken {
		t.Fatalf(
			"X-CSRF-Token = %q, want %q",
			resp.Header.Get("X-CSRF-Token"),
			registerResult.CSRFToken,
		)
	}

	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"Cache-Control = %q, want %q",
			resp.Header.Get("Cache-Control"),
			"no-store",
		)
	}

	//Проверка вызова сервиса
	if !service.called {
		t.Fatal("registration service was not called")
	}

	//Проверки полей тела ответа
	var respBody struct {
		ID            string    `json:"id"`
		Email         string    `json:"email"`
		DisplayName   string    `json:"display_name"`
		EmailVerified *bool     `json:"email_verified"`
		CreatedAt     time.Time `json:"created_at"`
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&respBody); err != nil {
		t.Fatalf("decode registration response: %v", err)
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

	//проверка куки
	cookies := resp.Cookies()
	const expectedCookies = 1

	if len(cookies) != expectedCookies {
		t.Fatalf("cookies = %d, want %d",
			len(cookies),
			expectedCookies,
		)
	}

	cookie := cookies[0]

	if cookie.Name != sessionCookieConfig.Name {
		t.Fatalf("cookie name = %q, want %q",
			cookie.Name,
			sessionCookieConfig.Name,
		)
	}

	if cookie.Value != registerResult.SessionToken {
		t.Fatalf("cookie value = %q, want %q",
			cookie.Value,
			registerResult.SessionToken,
		)
	}

	if cookie.Path != "/" {
		t.Fatalf("cookie path = %q, want /", cookie.Path)
	}

	if !cookie.Expires.Equal(registerResult.SessionExpiresAt) {
		t.Fatalf("cookie expires = %#v, want %#v",
			cookie.Expires,
			registerResult.SessionExpiresAt,
		)
	}

	if !cookie.HttpOnly {
		t.Fatalf("cookie httponly = %t, want %t",
			cookie.HttpOnly,
			true,
		)
	}

	if cookie.Secure != sessionCookieConfig.Secure {
		t.Fatalf("cookie secure = %t, want %t",
			cookie.Secure,
			false,
		)
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie same_site = %v, want %v",
			cookie.SameSite,
			http.SameSiteLaxMode,
		)
	}
}

func TestHandlerRegisterSetsSecureHostSessionCookie(t *testing.T) {
	createdAt := time.Date(
		2026,
		time.October,
		10,
		23,
		0,
		0,
		0,
		time.UTC,
	)
	sessionExpiresAt := createdAt.Add(30 * 24 * time.Hour)

	service := &fakeRegistrationService{
		result: authapp.RegisterResult{
			User: user.User{
				ID:          uuid.MustParse("22222222-2222-2222-2222-222222222222"),
				Email:       "user@example.com",
				DisplayName: "User",
				CreatedAt:   createdAt,
			},
			SessionToken:     "session-token",
			CSRFToken:        "csrf-token",
			SessionExpiresAt: sessionExpiresAt,
		},
	}

	cookieConfig := SessionCookieConfig{
		Name:   "__Host-session",
		Secure: true,
	}

	handler := NewHandler(service, cookieConfig)

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

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf(
			"response status = %d, want %d",
			resp.StatusCode,
			http.StatusCreated,
		)
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies count = %d, want 1", len(cookies))
	}

	cookie := cookies[0]

	if cookie.Name != cookieConfig.Name {
		t.Fatalf(
			"cookie name = %q, want %q",
			cookie.Name,
			cookieConfig.Name,
		)
	}

	if cookie.Value != service.result.SessionToken {
		t.Fatalf(
			"cookie value = %q, want %q",
			cookie.Value,
			service.result.SessionToken,
		)
	}

	if !cookie.Secure {
		t.Fatal("cookie Secure = false, want true")
	}

	if !cookie.HttpOnly {
		t.Fatal("cookie HttpOnly = false, want true")
	}

	if cookie.Path != "/" {
		t.Fatalf("cookie Path = %q, want %q", cookie.Path, "/")
	}

	if cookie.Domain != "" {
		t.Fatalf("cookie Domain = %q, want empty", cookie.Domain)
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf(
			"cookie SameSite = %v, want %v",
			cookie.SameSite,
			http.SameSiteLaxMode,
		)
	}

	if !cookie.Expires.Equal(sessionExpiresAt) {
		t.Fatalf(
			"cookie Expires = %v, want %v",
			cookie.Expires,
			sessionExpiresAt,
		)
	}
}

func TestHandlerRegisterDoesNotSetAuthArtifactsOnError(t *testing.T) {
	validBody := `{
		"email": "user@example.com",
		"display_name": "User",
		"password": "correct-password"
	}`

	tooLargeBody := `{"email":"` +
		strings.Repeat("a", (64<<10)+1) +
		`"}`

	tests := []struct {
		name        string
		contentType string
		body        string
		serviceErr  error
		wantStatus  int
	}{
		{
			name:        "unsupported media type",
			contentType: "text/plain",
			body:        `{}`,
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "invalid request body",
			contentType: "application/json",
			body:        `{"email":"`,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "request body too large",
			contentType: "application/json",
			body:        tooLargeBody,
			wantStatus:  http.StatusRequestEntityTooLarge,
		},
		{
			name:        "validation error",
			contentType: "application/json",
			body:        validBody,
			serviceErr: &authapp.ValidationError{
				Field:  "email",
				Reason: "must not be empty",
			},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:        "email already exists",
			contentType: "application/json",
			body:        validBody,
			serviceErr:  authapp.ErrEmailAlreadyExists,
			wantStatus:  http.StatusConflict,
		},
		{
			name:        "unexpected error",
			contentType: "application/json",
			body:        validBody,
			serviceErr:  errors.New("database connection lost"),
			wantStatus:  http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeRegistrationService{
				result: authapp.RegisterResult{
					SessionToken: "must-not-be-used",
					CSRFToken:    "must-not-be-used",
				},
				err: tc.serviceErr,
			}

			handler := NewHandler(
				service,
				SessionCookieConfig{
					Name:   "session",
					Secure: false,
				},
			)

			req := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/register",
				strings.NewReader(tc.body),
			)
			req.Header.Set("Content-Type", tc.contentType)

			rec := httptest.NewRecorder()

			handler.Register(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf(
					"response status = %d, want %d",
					resp.StatusCode,
					tc.wantStatus,
				)
			}

			if setCookie := resp.Header.Values("Set-Cookie"); len(setCookie) != 0 {
				t.Fatalf(
					"unexpected Set-Cookie headers: %q",
					setCookie,
				)
			}

			if csrfToken := resp.Header.Get("X-CSRF-Token"); csrfToken != "" {
				t.Fatalf(
					"unexpected X-CSRF-Token = %q",
					csrfToken,
				)
			}
		})
	}
}
