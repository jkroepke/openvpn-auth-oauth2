package testsuite

import (
	"log/slog"
)

func (s *Suite) Logs() string {
	return s.logger.String()
}

func (s *Suite) GetLogger() *slog.Logger {
	return s.logger.Logger()
}
