//go:build !windows

package gui

import (
	"errors"

	"github.com/netchx/netch-go/internal/config"
)

func Run(cfgPath string, cfg config.Config) error {
	return errors.New("gui: only supported on windows")
}
