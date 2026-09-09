package config

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
}

func Load() (Config, error) {
	//HTTPAddr
	cfg := Config{
		HTTPAddr:    "",
		DatabaseURL: "",
	}

	value, exists := os.LookupEnv("APP_HTTP_ADDR")
	value = strings.TrimSpace(value)

	defaulHTTPAddr := "127.0.0.1:18080"

	if !exists {
		cfg.HTTPAddr = defaulHTTPAddr
	}

	if value == "" {
		cfg.HTTPAddr = defaulHTTPAddr
	}

	cfg.HTTPAddr = value

	//DatabaseURL
	url, exists := os.LookupEnv("APP_DATABASE_URL")
	url = strings.TrimSpace(url)

	if !exists {
		return Config{}, errors.New("APP_DATABASE_URL environment must be set")
	}

	if url == "" {
		return Config{}, errors.New("APP_DATABASE_URL environment must not be empty")
	}

	cfg.DatabaseURL = url

	return cfg, nil
}
