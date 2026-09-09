package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	err = pool.Ping(ctx)
	if err != nil {
		pool.Close()

		return nil, fmt.Errorf("database unavailable: %w", err)
	}

	return pool, nil
}
