package sub

import (
	"context"
	"log/slog"
	"time"

	"github.com/netchx/netch-go/internal/config"
)

// AutoRefresh re-fetches the subscription on a timer and hands the parsed list
// to onUpdate. A failed refresh keeps the previous list and logs the reason.
func AutoRefresh(ctx context.Context, src string, interval time.Duration, timeout time.Duration, logger *slog.Logger, onUpdate func([]config.Server)) {
	if src == "" {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	logger.Info("subscription auto-refresh", "src", src, "interval", interval.String())

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			raw, err := Fetch(ctx, src, timeout)
			if err != nil {
				logger.Warn("subscription refresh fetch", "err", err)
				continue
			}
			servers, err := ParseList(raw)
			if err != nil && len(servers) == 0 {
				logger.Warn("subscription refresh parse", "err", err)
				continue
			}
			onUpdate(servers)
			logger.Info("subscription refreshed", "count", len(servers))
		}
	}
}
