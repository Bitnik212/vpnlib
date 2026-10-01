// Package main is the native VPN core of vpnlib. It is compiled as a
// c-shared library for Android and a c-archive for iOS; the exported C API is
// documented in include/vpncore.h.
package main

/*
#include <stdlib.h>
#include "callbacks.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	xraycore "github.com/xtls/xray-core/core"
)

const (
	logDebug = 0
	logInfo  = 1
	logWarn  = 2
	logError = 3
)

var (
	callbacksMu sync.RWMutex
	logFn       C.vpncore_log_fn
	protectFn   C.vpncore_protect_fn

	lastErrMu sync.Mutex
	lastErr   string

	handlesMu  sync.Mutex
	nextHandle int32
	tunnels    = map[int32]tunnel{}
)

// tunnel is a running engine instance.
type tunnel interface {
	stop()
}

func main() {}

func logf(level int32, tag string, format string, args ...any) {
	callbacksMu.RLock()
	fn := logFn
	callbacksMu.RUnlock()
	if fn == nil {
		return
	}
	cTag := C.CString(tag)
	cMsg := C.CString(fmt.Sprintf(format, args...))
	C.vpncore_invoke_log(fn, C.int32_t(level), cTag, cMsg)
	C.free(unsafe.Pointer(cTag))
	C.free(unsafe.Pointer(cMsg))
}

func setLastError(err error) {
	lastErrMu.Lock()
	lastErr = err.Error()
	lastErrMu.Unlock()
	logf(logError, "vpncore", "%v", err)
}

func fail(format string, args ...any) C.int32_t {
	setLastError(fmt.Errorf(format, args...))
	return -1
}

func registerTunnel(t tunnel) int32 {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	for {
		h := nextHandle
		nextHandle = (nextHandle + 1) & 0x7fffffff
		if _, used := tunnels[h]; !used {
			tunnels[h] = t
			return h
		}
	}
}

func lookupTunnel(handle C.int32_t) tunnel {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	return tunnels[int32(handle)]
}

func removeTunnel(handle C.int32_t) tunnel {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	t := tunnels[int32(handle)]
	delete(tunnels, int32(handle))
	return t
}

// protectFd excludes a socket from the VPN through the platform callback.
func protectFd(fd uintptr) error {
	callbacksMu.RLock()
	fn := protectFn
	callbacksMu.RUnlock()
	if fn == nil {
		return nil
	}
	if C.vpncore_invoke_protect(fn, C.int32_t(fd)) == 0 {
		return fmt.Errorf("failed to protect socket %d", fd)
	}
	return nil
}

// protectRawConn adapts protectFd to net.Dialer.Control / xray controllers.
func protectRawConn(_, _ string, c syscall.RawConn) error {
	var protectErr error
	if err := c.Control(func(fd uintptr) { protectErr = protectFd(fd) }); err != nil {
		return err
	}
	return protectErr
}

func hasProtector() bool {
	callbacksMu.RLock()
	defer callbacksMu.RUnlock()
	return protectFn != nil
}

//export vpncoreVersion
func vpncoreVersion() *C.char {
	return C.CString(fmt.Sprintf("vpncore/%s xray-core/%s amneziawg-go/%s", coreVersion, xraycore.Version(), awgVersion()))
}

//export vpncoreLastError
func vpncoreLastError() *C.char {
	lastErrMu.Lock()
	defer lastErrMu.Unlock()
	if lastErr == "" {
		return nil
	}
	return C.CString(lastErr)
}

//export vpncoreFree
func vpncoreFree(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

//export vpncoreSetLogger
func vpncoreSetLogger(fn C.vpncore_log_fn) {
	callbacksMu.Lock()
	logFn = fn
	callbacksMu.Unlock()
}

//export vpncoreSetProtector
func vpncoreSetProtector(fn C.vpncore_protect_fn) {
	callbacksMu.Lock()
	protectFn = fn
	callbacksMu.Unlock()
	if fn != nil {
		installXrayProtector()
	}
}

var dnsServers atomic.Pointer[[]string]

//export vpncoreSetDnsServers
func vpncoreSetDnsServers(servers *C.char) {
	var list []string
	for _, s := range strings.Split(C.GoString(servers), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		list = append(list, s)
	}
	dnsServers.Store(&list)
	if len(list) == 0 {
		net.DefaultResolver = &net.Resolver{}
		return
	}
	// Go's pure resolver reads /etc/resolv.conf, which does not exist on
	// Android, so point it at explicit servers and keep its sockets out of the
	// tunnel to avoid routing loops.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			servers := *dnsServers.Load()
			dialer := net.Dialer{Control: protectRawConn}
			var errs []error
			for _, server := range servers {
				conn, err := dialer.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
}

//export vpncoreSetMemoryLimit
func vpncoreSetMemoryLimit(bytes C.int64_t) {
	debug.SetMemoryLimit(int64(bytes))
}
