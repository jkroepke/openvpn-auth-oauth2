package log

import (
	"context"
	"log/slog"

	expslog "golang.org/x/exp/slog"
)

type SLogHandler struct {
	logger      *slog.Logger
	levelMapper map[expslog.Level]slog.Level
}

func NewZitadelLogger(logger *slog.Logger) *expslog.Logger {
	return expslog.New(newSlogHandler(logger))
}

func newSlogHandler(logger *slog.Logger) *SLogHandler {
	return &SLogHandler{
		logger,
		map[expslog.Level]slog.Level{
			expslog.LevelDebug: slog.LevelDebug,
			expslog.LevelInfo:  slog.LevelInfo,
			expslog.LevelWarn:  slog.LevelWarn,
			expslog.LevelError: slog.LevelError,
		},
	}
}

func (handler SLogHandler) Enabled(ctx context.Context, level expslog.Level) bool {
	return handler.logger.Enabled(ctx, handler.convertLevel(level))
}

func (handler SLogHandler) Handle(ctx context.Context, expRecord expslog.Record) error {
	record := slog.NewRecord(expRecord.Time, handler.convertLevel(expRecord.Level), expRecord.Message, expRecord.PC)

	return handler.logger.Handler().Handle(ctx, record) //nolint:wrapcheck
}

func (handler SLogHandler) WithAttrs(attrs []expslog.Attr) expslog.Handler {
	logger := handler.logger
	for _, attr := range attrs {
		logger = logger.With(attr.Key, attr.Value.String())
	}

	return &SLogHandler{logger, handler.levelMapper}
}

func (handler SLogHandler) WithGroup(name string) expslog.Handler {
	return &SLogHandler{handler.logger.WithGroup(name), handler.levelMapper}
}

func (handler SLogHandler) convertLevel(expLevel expslog.Level) slog.Level {
	level, ok := handler.levelMapper[expLevel]
	if ok {
		return level
	}

	bytes, err := expLevel.MarshalText()
	if err != nil {
		panic(err)
	}

	if err = level.UnmarshalText(bytes); err != nil {
		panic(err)
	}

	return level
}
