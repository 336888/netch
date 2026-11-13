//go:build !windows

package gui

import (
	"errors"

	"github.com/netchx/netch-go/internal/config"
)

func Run(cfgPath string, cfg config.Config) error {
	return errors.New("gui: only supported on windows")
}

// ShowError prints to stderr on non-Windows platforms.
func ShowError(title string, err error) {
	if err == nil {
		return
	}
	println(title+":", err.Error())
}
