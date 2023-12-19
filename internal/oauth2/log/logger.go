package log

import (
	"context"
	"log/slog"

	expslog "golang.org/x/exp/slog"
)

var LogLevelMapper = map[expslog.Level]slog.Level{
	expslog.LevelDebug: slog.LevelDebug,
	expslog.LevelInfo:  slog.LevelInfo,
	expslog.LevelWarn:  slog.LevelWarn,
	expslog.LevelError: slog.LevelError,
}

type LogSLogHandler struct {
	logger *slog.Logger
}

func NewZitadelLogger(logger *slog.Logger) *expslog.Logger {
	return expslog.New(newSlogHandler(logger))
}

func newSlogHandler(logger *slog.Logger) *LogSLogHandler {
	return &LogSLogHandler{logger}
}

func (h LogSLogHandler) Enabled(ctx context.Context, level expslog.Level) bool {

	return h.logger.Enabled(ctx, convertSLogLevel(level))
}

func (h LogSLogHandler) Handle(ctx context.Context, expRecord expslog.Record) error {
	record := slog.NewRecord(expRecord.Time, convertSLogLevel(expRecord.Level), expRecord.Message, expRecord.PC)
	return h.logger.Handler().Handle(ctx, record)
}

func (h LogSLogHandler) WithAttrs(attrs []expslog.Attr) expslog.Handler {
	logger := h.logger
	for _, attr := range attrs {
		logger = logger.With(attr.Key, attr.Value.String())
	}

	return &LogSLogHandler{logger}
}

func (h LogSLogHandler) WithGroup(name string) expslog.Handler {
	return &LogSLogHandler{h.logger.WithGroup(name)}
}

func convertSLogLevel(expLevel expslog.Level) slog.Level {
	level, ok := LogLevelMapper[expLevel]
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
