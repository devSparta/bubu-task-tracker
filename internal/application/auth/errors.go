package auth

import (
	"errors"
	"fmt"
)

var ErrEmailAlreadyExists = errors.New("email already exists")

type ValidationError struct {
	Field  string
	Reason string
}

// Реализация встроенного интерфейся error структурой ValidationError
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}
