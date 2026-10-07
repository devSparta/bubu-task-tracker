package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	authapp "github.com/devSparta/bubu-task-tracker/internal/application/auth"
	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool: pool,
	}
}

func (r *UserRepository) CreateUserWithSession(
	ctx context.Context,
	params authapp.CreateUserWithSessionParams,
) (user.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return user.User{}, fmt.Errorf("begin registration transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const queryUser = "INSERT INTO users (email, display_name, password_hash) " +
		"VALUES ($1, $2, $3) " +
		"RETURNING id, email, display_name, email_verified_at, created_at, updated_at, status"

	createdUser := user.User{}

	err = tx.QueryRow(ctx, queryUser, params.User.Email, params.User.DisplayName, params.User.PasswordHash).Scan(
		&createdUser.ID,
		&createdUser.Email,
		&createdUser.DisplayName,
		&createdUser.EmailVerifiedAt,
		&createdUser.CreatedAt,
		&createdUser.UpdatedAt,
		&createdUser.Status,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_idx" {
				return user.User{}, authapp.ErrEmailAlreadyExists
			}
		}

		return user.User{}, fmt.Errorf("insert user: %w", err)
	}

	const querySession = "INSERT INTO sessions " +
		"(user_id, token_hash, csrf_token_hash, created_at, last_seen_at, expires_at, absolute_expires_at) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7)"

	_, err = tx.Exec(ctx, querySession,
		createdUser.ID,
		params.Session.TokenHash,
		params.Session.CSRFTokenHash,
		params.Session.CreatedAt,
		params.Session.LastSeenAt,
		params.Session.ExpiresAt,
		params.Session.AbsoluteExpiresAt,
	)

	if err != nil {
		return user.User{}, fmt.Errorf("insert session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return user.User{}, fmt.Errorf("commit registration transaction: %w", err)
	}

	return createdUser, nil
}
