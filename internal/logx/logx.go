package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func New(level string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: parse(level),
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format("15:04:05.000"))
			}
			return a
		},
	})
	return slog.New(h)
}

func parse(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
