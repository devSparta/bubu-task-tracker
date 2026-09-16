package postgres

import (
	"context"
	"fmt"

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

func (r *UserRepository) Create(
	ctx context.Context,
	params authapp.CreateUserParams,
) (user.User, error) {
	const query = "INSERT INTO users (email, display_name, password_hash) " +
		"VALUES ($1, $2, $3) " +
		"RETURNING id, email, display_name, email_verified_at, created_at, updated_at"

	createdUser := user.User{}

	err := r.pool.QueryRow(ctx, query, params.Email, params.DisplayName, params.PasswordHash).Scan(
		&createdUser.ID,
		&createdUser.Email,
		&createdUser.DisplayName,
		&createdUser.EmailVerifiedAt,
		&createdUser.CreatedAt,
		&createdUser.UpdatedAt,
	)

	if err != nil {
		return user.User{}, fmt.Errorf("insert user: %w", err)
	}

	return createdUser, nil
}
