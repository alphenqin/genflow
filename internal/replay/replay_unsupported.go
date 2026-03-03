//go:build !linux

package replay

import "errors"

func Replay(cfg Config) error {
	_ = cfg
	return errors.New("replay is only supported on linux (requires AF_PACKET raw socket)")
}
