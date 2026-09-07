package config

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	HTTPAddr string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr: "127.0.0.1:18080",
	}

	value, exists := os.LookupEnv("APP_HTTP_ADDR")
	value = strings.TrimSpace(value)

	if !exists {
		return cfg, nil
	}

	if value == "" {
		return Config{}, errors.New("APP_HTTP_ADDR environment must not be empty")
	}

	cfg.HTTPAddr = value
	return cfg, nil
}
