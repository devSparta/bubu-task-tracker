package user

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
)

func (s Status) isValid() bool {
	switch s {
	case StatusActive, StatusBlocked:
		return true

	default:
		return false
	}
}
