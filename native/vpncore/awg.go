package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime/debug"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"golang.org/x/sys/unix"
)

// awgTunnel runs a WireGuard / AmneziaWG device. amneziawg-go speaks plain
// WireGuard when no obfuscation parameters are configured.
type awgTunnel struct {
	dev *device.Device
}

func (t *awgTunnel) stop() {
	t.dev.Close()
}

func awgVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/amnezia-vpn/amneziawg-go" {
				return dep.Version
			}
		}
	}
	return "unknown"
}

func newAwgLogger(tag string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { logf(logDebug, tag, format, args...) },
		Errorf:   func(format string, args ...any) { logf(logError, tag, format, args...) },
	}
}

//export vpncoreAwgTurnOn
func vpncoreAwgTurnOn(tunFd C.int32_t, settings *C.char) C.int32_t {
	fd, err := unix.Dup(int(tunFd))
	if err != nil {
		return fail("dup tun fd: %v", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return fail("set tun fd non-blocking: %v", err)
	}
	// createTun takes ownership of fd, it is closed together with the device.
	tunDev, name, err := createTun(fd)
	if err != nil {
		unix.Close(fd)
		return fail("create tun device: %v", err)
	}

	logger := newAwgLogger("awg/" + name)
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		dev.Close()
		return fail("configure device: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fail("bring device up: %v", err)
	}
	if err := protectAwgSockets(dev); err != nil {
		dev.Close()
		return fail("protect sockets: %v", err)
	}
	logf(logInfo, "awg", "device %s is up", name)
	return C.int32_t(registerTunnel(&awgTunnel{dev: dev}))
}

// protectAwgSockets excludes the UDP sockets of the device from the tunnel
// on platforms that need it (Android).
func protectAwgSockets(dev *device.Device) error {
	if !hasProtector() {
		return nil
	}
	bind, ok := dev.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return nil
	}
	if fd, err := bind.PeekLookAtSocketFd4(); err == nil {
		if err := protectFd(uintptr(fd)); err != nil {
			return err
		}
	}
	if fd, err := bind.PeekLookAtSocketFd6(); err == nil {
		if err := protectFd(uintptr(fd)); err != nil {
			return err
		}
	}
	return nil
}

//export vpncoreAwgTurnOff
func vpncoreAwgTurnOff(handle C.int32_t) {
	if t, ok := removeTunnel(handle).(*awgTunnel); ok {
		t.stop()
	}
}

//export vpncoreAwgGetConfig
func vpncoreAwgGetConfig(handle C.int32_t) *C.char {
	t, ok := lookupTunnel(handle).(*awgTunnel)
	if !ok {
		setLastError(fmt.Errorf("unknown wireguard handle %d", handle))
		return nil
	}
	cfg, err := t.dev.IpcGet()
	if err != nil {
		setLastError(err)
		return nil
	}
	return C.CString(cfg)
}

//export vpncoreAwgBumpSockets
func vpncoreAwgBumpSockets(handle C.int32_t) {
	t, ok := lookupTunnel(handle).(*awgTunnel)
	if !ok {
		return
	}
	go func() {
		if err := t.dev.BindUpdate(); err != nil {
			logf(logWarn, "awg", "bind update failed: %v", err)
			return
		}
		if err := protectAwgSockets(t.dev); err != nil {
			logf(logWarn, "awg", "protect after bind update failed: %v", err)
		}
		t.dev.SendKeepalivesToPeersWithCurrentKeypair()
	}()
}
