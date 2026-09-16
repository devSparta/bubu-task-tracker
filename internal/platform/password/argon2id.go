package password

import (
	"github.com/alexedwards/argon2id"
)

type Argon2ID struct {
	params argon2id.Params
}

func NewArgon2ID() *Argon2ID {
	return &Argon2ID{
		params: argon2id.Params{
			Memory:      19 * 1024,
			Iterations:  2,
			Parallelism: 1,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

// создаёт Argon2id-хеш пароля password
func (h *Argon2ID) Hash(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, &h.params)
	if err != nil {
		return "", err
	}

	return hash, nil
}
