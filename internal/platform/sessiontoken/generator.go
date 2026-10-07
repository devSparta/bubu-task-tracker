package sessiontoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Generate() (string, []byte, error) {
	const tokenSizeBytes = 32

	randomBytes := make([]byte, tokenSizeBytes)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf(
			"generate random token: %w",
			err,
		)
	}

	token := base64.RawURLEncoding.EncodeToString(randomBytes)
	hashArray := sha256.Sum256([]byte(token))

	return token, hashArray[:], nil
}
