package clock

import "time"

type System struct{}

func New() *System {
	return &System{}
}

func (s *System) Now() time.Time {
	return time.Now().UTC()
}
