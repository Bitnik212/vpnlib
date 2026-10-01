/*
 * vpncore — native VPN engine used by vpnlib (Android & iOS).
 *
 * Built from Go (see ../vpncore/*.go) as a c-shared library for Android
 * (libvpncore.so, called through the bundled JNI shim) and as a c-archive for
 * iOS (libvpncore.a inside VpnCore.xcframework, called through Kotlin/Native
 * cinterop). Keep this header in sync with the //export functions.
 *
 * Conventions:
 *  - Functions that start an engine return a handle >= 0 on success or a
 *    negative value on failure; call vpncoreLastError() for the reason.
 *  - Strings returned by the library are heap allocated and must be released
 *    with vpncoreFree().
 *  - Tunnel file descriptors are never taken over: the engine works on its own
 *    dup() of the descriptor, so the caller keeps ownership of the original.
 */
#ifndef VPNCORE_H
#define VPNCORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels passed to vpncore_log_fn. */
#define VPNCORE_LOG_DEBUG 0
#define VPNCORE_LOG_INFO 1
#define VPNCORE_LOG_WARN 2
#define VPNCORE_LOG_ERROR 3

typedef void (*vpncore_log_fn)(int32_t level, const char *tag, const char *message);

/* Returns non-zero when the socket was excluded from the tunnel. */
typedef int32_t (*vpncore_protect_fn)(int32_t fd);

/* ---- general ---------------------------------------------------------- */

char *vpncoreVersion(void);
char *vpncoreLastError(void);
void vpncoreFree(void *ptr);

void vpncoreSetLogger(vpncore_log_fn fn);

/* Android: excludes sockets of the engines from the VPN (VpnService.protect).
 * Not needed on iOS, where NetworkExtension sockets bypass the tunnel. */
void vpncoreSetProtector(vpncore_protect_fn fn);

/* Comma separated "ip:port" list used by the Go resolver for hostnames inside
 * engine configs. Required on Android, where /etc/resolv.conf is missing. */
void vpncoreSetDnsServers(const char *servers);

/* Soft memory limit for the Go runtime in bytes (iOS extensions are capped). */
void vpncoreSetMemoryLimit(int64_t bytes);

/* ---- WireGuard / AmneziaWG (amneziawg-go) ------------------------------ */

/* settings: wireguard UAPI "set" body. Plain WireGuard when no AmneziaWG
 * keys are present. */
int32_t vpncoreAwgTurnOn(int32_t tunFd, const char *settings);
void vpncoreAwgTurnOff(int32_t handle);
/* UAPI "get" output (includes rx_bytes / tx_bytes / handshake times). */
char *vpncoreAwgGetConfig(int32_t handle);
/* Re-binds sockets after a network change (iOS path updates). */
void vpncoreAwgBumpSockets(int32_t handle);

/* ---- Xray (xray-core) ------------------------------------------------- */

/* configJson: complete Xray JSON config with a "tun" inbound. Only one Xray
 * instance can run at a time. */
int32_t vpncoreXrayStart(int32_t tunFd, const char *configJson);
void vpncoreXrayStop(int32_t handle);
/* "uplink=<bytes>\ndownlink=<bytes>\n" summed over all outbounds with stats. */
char *vpncoreXrayGetStats(int32_t handle);

#ifdef __cplusplus
}
#endif

#endif /* VPNCORE_H */
