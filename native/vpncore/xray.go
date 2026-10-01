package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	applog "github.com/xtls/xray-core/app/log"
	commonlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/platform"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"

	// Registers every protocol, transport and the JSON config loader.
	_ "github.com/xtls/xray-core/main/distro/all"
)

var (
	xrayMu      sync.Mutex
	xrayRunning bool

	xrayProtectOnce sync.Once
)

func init() {
	// Route Xray's console logs to the platform logger instead of stdout,
	// which is discarded on Android and iOS.
	_ = applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (commonlog.Handler, error) {
		return commonlog.NewLogger(func() commonlog.Writer { return xrayLogWriter{} }), nil
	})
}

type xrayLogWriter struct{}

func (xrayLogWriter) Write(s string) error {
	level := int32(logInfo)
	switch {
	case strings.Contains(s, "[Debug]"):
		level = logDebug
	case strings.Contains(s, "[Warning]"):
		level = logWarn
	case strings.Contains(s, "[Error]"):
		level = logError
	}
	logf(level, "xray", "%s", s)
	return nil
}

func (xrayLogWriter) Close() error { return nil }

// installXrayProtector keeps every socket Xray opens out of the tunnel.
// Controllers can only be added, so this happens once per process and the
// controller itself consults the current protector.
func installXrayProtector() {
	xrayProtectOnce.Do(func() {
		if err := internet.RegisterDialerController(protectRawConn); err != nil {
			logf(logWarn, "xray", "register dialer controller: %v", err)
		}
		if err := internet.RegisterListenerController(protectRawConn); err != nil {
			logf(logWarn, "xray", "register listener controller: %v", err)
		}
	})
}

// counterVisitor is implemented by xray's app/stats manager.
type counterVisitor interface {
	VisitCounters(func(string, stats.Counter) bool)
}

type xrayTunnel struct {
	instance *xraycore.Instance
	tunFd    int
}

func (t *xrayTunnel) stop() {
	if err := t.instance.Close(); err != nil {
		logf(logWarn, "xray", "close instance: %v", err)
	}
	// The tun inbound never closes a descriptor it was handed, the dup is ours.
	unix.Close(t.tunFd)
	xrayMu.Lock()
	xrayRunning = false
	xrayMu.Unlock()
}

//export vpncoreXrayStart
func vpncoreXrayStart(tunFd C.int32_t, configJSON *C.char) C.int32_t {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayRunning {
		return fail("an xray instance is already running")
	}

	fd, err := unix.Dup(int(tunFd))
	if err != nil {
		return fail("dup tun fd: %v", err)
	}
	// Xray's tun inbound picks the descriptor up from the environment.
	if err := os.Setenv(platform.TunFdKey, strconv.Itoa(fd)); err != nil {
		unix.Close(fd)
		return fail("export tun fd: %v", err)
	}

	instance, err := xraycore.StartInstance("json", []byte(C.GoString(configJSON)))
	if err != nil {
		unix.Close(fd)
		return fail("start xray: %v", err)
	}
	xrayRunning = true
	logf(logInfo, "xray", "xray %s started", xraycore.Version())
	return C.int32_t(registerTunnel(&xrayTunnel{instance: instance, tunFd: fd}))
}

//export vpncoreXrayStop
func vpncoreXrayStop(handle C.int32_t) {
	if t, ok := removeTunnel(handle).(*xrayTunnel); ok {
		t.stop()
	}
}

//export vpncoreXrayGetStats
func vpncoreXrayGetStats(handle C.int32_t) *C.char {
	t, ok := lookupTunnel(handle).(*xrayTunnel)
	if !ok {
		setLastError(fmt.Errorf("unknown xray handle %d", handle))
		return nil
	}
	var uplink, downlink int64
	// The stats feature is only present when the config enables "stats".
	if manager, ok := t.instance.GetFeature(stats.ManagerType()).(counterVisitor); ok {
		manager.VisitCounters(func(name string, counter stats.Counter) bool {
			// Counter names look like "outbound>>>proxy>>>traffic>>>uplink".
			parts := strings.Split(name, ">>>")
			if len(parts) == 4 && parts[0] == "outbound" && parts[2] == "traffic" {
				switch parts[3] {
				case "uplink":
					uplink += counter.Value()
				case "downlink":
					downlink += counter.Value()
				}
			}
			return true
		})
	}
	return C.CString(fmt.Sprintf("uplink=%d\ndownlink=%d\n", uplink, downlink))
}
