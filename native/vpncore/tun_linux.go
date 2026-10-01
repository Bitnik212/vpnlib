//go:build linux || android

package main

import "github.com/amnezia-vpn/amneziawg-go/tun"

// createTun wraps a tun fd handed over by Android's VpnService.
func createTun(fd int) (tun.Device, string, error) {
	return tun.CreateUnmonitoredTUNFromFD(fd)
}
