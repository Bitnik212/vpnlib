//go:build darwin || ios

package main

import (
	"os"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// createTun wraps the utun fd owned by NEPacketTunnelProvider.
func createTun(fd int) (tun.Device, string, error) {
	dev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/tun"), 0)
	if err != nil {
		return nil, "", err
	}
	name, err := dev.Name()
	if err != nil {
		name = "utun"
	}
	return dev, name, nil
}
