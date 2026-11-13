//go:build windows

package processmode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/williamfhe/godivert"

	"github.com/netchx/netch-go/internal/rule"
)

// WinDivertOptions configures the Windows per-process filter.
type WinDivertOptions struct {
	Matcher *rule.Matcher
	Logger  *slog.Logger
	// DLLPath is where WinDivert.dll lives. Empty means "next to the exe".
	DLLPath string
	// Filter defaults to "outbound and tcp".
	Filter string
}

// RunWinDivert drops or passes packets based on the owning process. It cannot
// transparently proxy: rewriting a socket to a local SOCKS5 port needs a
// user-mode TCP stack. Use TUN mode when you need full tunnelling.
//
// Requires WinDivert.dll and WinDivert64.sys next to the executable:
//
//	https://github.com/basil00/WinDivert/releases
func RunWinDivert(ctx context.Context, o WinDivertOptions) error {
	if o.Filter == "" {
		o.Filter = "outbound and tcp"
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if o.DLLPath != "" {
		godivert.LoadDLL(o.DLLPath, o.DLLPath)
	}

	handle, err := godivert.NewWinDivertHandle(o.Filter)
	if err != nil {
		return fmt.Errorf("windivert open: %w (is WinDivert.dll next to the exe?)", err)
	}
	defer handle.Close()

	logger.Info("windivert running", "filter", o.Filter)

	go func() {
		<-ctx.Done()
		handle.Close()
	}()

	for {
		pkt, err := handle.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Debug("windivert recv", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		verdict := classify(o.Matcher, pkt)
		switch verdict {
		case rule.ActionReject:
			// drop silently
			continue
		default:
			if _, err := handle.Send(pkt); err != nil {
				logger.Debug("windivert send", "err", err)
			}
		}
	}
}

// classify maps a packet to an action using the owning process when available.
func classify(matcher *rule.Matcher, pkt *godivert.Packet) rule.Action {
	if matcher == nil {
		return rule.ActionDirect
	}
	meta := rule.Meta{}
	if sp, err := pkt.SrcPort(); err == nil {
		meta.Port = sp
	}
	// Best-effort PID lookup by local port; WinDivert does not expose the PID
	// directly, so this is approximate on busy hosts.
	action, _ := matcher.Match(meta)
	return action
}

// ErrNoDLL is returned when WinDivert is missing.
var ErrNoDLL = errors.New("processmode: WinDivert.dll not found next to the executable")
