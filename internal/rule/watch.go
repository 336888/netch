package rule

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

// Watch reloads the rule file whenever its mtime changes. Errors are logged and
// the previous matcher stays active, so a typo never takes the proxy down.
func Watch(ctx context.Context, path string, logger *slog.Logger, apply func(*Matcher)) {
	if path == "" {
		return
	}
	var lastMod time.Time
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := os.Stat(path)
			if err != nil {
				continue
			}
			mod := st.ModTime()
			if mod.Equal(lastMod) {
				continue
			}
			lastMod = mod

			raw, err := os.ReadFile(path)
			if err != nil {
				logger.Warn("rules reload read", "err", err)
				continue
			}
			var rules []Rule
			if err := json.Unmarshal(raw, &rules); err != nil {
				logger.Warn("rules reload parse", "err", err)
				continue
			}
			m, err := New(rules)
			if err != nil {
				logger.Warn("rules reload validate", "err", err)
				continue
			}
			apply(m)
			logger.Info("rules reloaded", "count", m.Len())
		}
	}
}
