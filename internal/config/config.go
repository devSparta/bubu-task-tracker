package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HTTPAddr              string
	DatabaseURL           string
	IsSessionCookieSecure bool
}

func Load() (Config, error) {
	//HTTPAddr
	cfg := Config{
		HTTPAddr:    "127.0.0.1:18080",
		DatabaseURL: "",
	}

	addr, exists := os.LookupEnv("APP_HTTP_ADDR")

	if addr == " " {
		return Config{}, errors.New("APP_HTTP_ADDR environment must be set")
	}

	addr = strings.TrimSpace(addr)

	if exists && addr != "" {
		cfg.HTTPAddr = addr
	}

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

	//isSecureCookie
	rawCookieSecure, exists := os.LookupEnv("APP_SESSION_COOKIE_SECURE")
	if !exists {
		return Config{}, errors.New("APP_SESSION_COOKIE_SECURE environment must be set")
	}

	rawCookieSecure = strings.TrimSpace(rawCookieSecure)

	isCookieSecure, err := strconv.ParseBool(rawCookieSecure)
	if err != nil {
		return Config{}, errors.New("APP_SESSION_COOKIE_SECURE is not a boolean value")
	}

	cfg.IsSessionCookieSecure = isCookieSecure

	return cfg, nil
}
