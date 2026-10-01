# vpnlib

Kotlin Multiplatform library for building VPN clients on **Android** and **iOS** with
**WireGuard**, **AmneziaWG** and **Xray** (VLESS / VMess / Trojan / Shadowsocks, incl. REALITY).

```
┌──────────────────────────── commonMain (Kotlin) ────────────────────────────┐
│ VpnProfile ─ WireGuardConfig / AmneziaWgConfig / XrayConfig                 │
│ WgQuickFormat (.conf)  XrayShareLink (vless://…)  XrayJsonBuilder  WgUapi   │
│ TunnelPlanner → TunnelPlan (addresses, routes, DNS, MTU, engine config)     │
│ TunnelSession ── VpnCore (interface)          VpnController (interface)     │
└───────────────┬─────────────────────────────────────────┬───────────────────┘
   androidMain  │ VpnLibService (VpnService)              │ iosMain  PacketTunnelEngine (NE)
                │ AndroidVpnController                    │          IosVpnController
                │ JNI → libvpncore.so                     │ cinterop → libvpncore.a
┌───────────────┴─────────────── native/vpncore (Go) ─────┴───────────────────┐
│ amneziawg-go (WireGuard + AmneziaWG)      xray-core (native "tun" inbound)  │
└─────────────────────────────────────────────────────────────────────────────┘
```

* One native core written in Go (`native/vpncore`) exposes a small C API
  (`include/vpncore.h`). amneziawg-go speaks plain WireGuard when no obfuscation
  parameters are set, so it serves both WireGuard and AmneziaWG. Xray-core reads
  packets directly from the tunnel fd through its `tun` inbound (no tun2socks,
  no local SOCKS port).
* Everything protocol-specific that does not touch the OS — parsing, validation,
  route math, UAPI / Xray JSON generation — lives in `commonMain` and is unit
  tested on the JVM target.
* Platform code only creates the tunnel interface and drives the engine.

## Modules and layout

| Path | Contents |
| --- | --- |
| `vpnlib/src/commonMain` | configs, parsers, planner, session, controller API |
| `vpnlib/src/androidMain` | `VpnLibService`, `AndroidVpnController`, JNI bindings |
| `vpnlib/src/iosMain` | `PacketTunnelEngine`, `IosVpnController`, cinterop bindings |
| `jvm()` target | host target for config tooling and fast tests of the shared code |
| `native/vpncore` | Go engine + JNI shim, C header |
| `native/build-android.sh`, `native/build-ios.sh` | native builds |
| `ios/` | Swift templates for the Packet Tunnel extension and app |

## Building

Requirements: JDK 17+, Go (see `native/vpncore/go.mod`; `GOTOOLCHAIN=auto` works),
Android SDK + NDK for Android, macOS + Xcode for iOS.

```bash
# Android: native core for all ABIs, then the AAR
ANDROID_NDK_HOME=/path/to/ndk native/build-android.sh     # or ./gradlew buildVpnCoreAndroid
./gradlew :vpnlib:assembleRelease

# iOS: VpnCore.xcframework (Go) and VpnLib.xcframework (Kotlin, static)
native/build-ios.sh                                        # or ./gradlew buildVpnCoreIos
./gradlew :vpnlib:assembleVpnLibXCFramework

# Shared code tests
./gradlew :vpnlib:jvmTest
```

The Android build packages `native/build/android/jniLibs/<abi>/libvpncore.so`
(16 KB page aligned). On iOS, link both `VpnLib.xcframework` and
`VpnCore.xcframework` into the Network Extension target (and `VpnLib` into the app).

## Usage

### Configs

```kotlin
// WireGuard or AmneziaWG .conf (AmneziaWG keys Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 are detected)
val wg: WgBasedConfig = WgQuickFormat.parse(confText)

// Xray from a share link …
val xray = XrayConfig.fromShareLink("vless://uuid@host:443?security=reality&pbk=…&sni=…#Name")
// … or a full Xray JSON config (the tun inbound is injected)
val custom = XrayConfig.fromJson(json)

val profile = VpnProfile(
    id = "home",
    name = "Home",
    config = wg,
    options = TunnelOptions(allowLanAccess = true, excludedApplications = listOf("com.bank")),
)
```

### Android

The library manifest declares `VpnLibService`. Ask for VPN consent once, then connect:

```kotlin
val vpn = AndroidVpnController(context)
vpn.prepare()?.let { consentLauncher.launch(it) }   // ActivityResultContracts.StartActivityForResult
lifecycleScope.launch {
    vpn.connect(profile)
    vpn.state.collect { state -> render(state) }
}
vpn.statistics()   // rx/tx bytes, last handshake
vpn.disconnect()
```

Subclass `VpnLibService` to customize the notification (`createNotification`) or
`VpnService.Builder` (`configureBuilder`), declare the subclass in your manifest
(see `vpnlib/src/androidMain/AndroidManifest.xml`) and pass it to
`AndroidVpnController(context, MyVpnService::class.java)`. Always-on VPN restarts
the last connected profile. The service must run in the app's main process.

### iOS

1. Add a Packet Tunnel Network Extension target and copy
   [`ios/PacketTunnelProvider.swift`](ios/PacketTunnelProvider.swift) into it.
2. Enable the Network Extensions (Packet Tunnel) capability on the app and the extension.
3. Control the tunnel from the app (see [`ios/VpnExample.swift`](ios/VpnExample.swift)):

```swift
let vpn = IosVpnController(providerBundleIdentifier: "com.example.app.tunnel")
try await vpn.load()
try await vpn.connect(profile: profile)
```

Note: the extension process is limited to ~50 MB of memory. The Go heap limit is
set to 30 MB by default (`PacketTunnelEngine.memoryLimitBytes`); complex Xray
configs may need tuning.

## How it works

* `TunnelPlanner` validates the profile, resolves server hostnames with the
  platform resolver (before the tunnel exists, so the lookup can't loop through
  it), and computes routes. Exclusions (`excludedRoutes`, `allowLanAccess`) are
  applied by subtracting prefixes, so they also work on Android < 13.
* WireGuard/AmneziaWG get a UAPI config (`WgUapi`); Xray gets a generated JSON
  config with a `tun` inbound, DNS hijacking to Xray's DNS module, private ranges
  routed `direct`, and stats counters for `TunnelStatistics`.
* On Android every engine socket is excluded from the VPN through
  `VpnService.protect` (JNI callback from Go). On iOS, NetworkExtension
  sockets bypass the tunnel automatically.
* Engines work on a `dup()` of the tunnel fd; the platform keeps ownership of the original.

## Security notes

* Profiles (including private keys) are stored in app-private SharedPreferences on
  Android (for always-on restarts) and in the NE `providerConfiguration` on iOS.
  Use `AndroidVpnController.clearSavedProfile()` / `IosVpnController.removeConfiguration()`
  to drop them; consider moving secrets to the Keychain / Keystore in your app.
* `allowInsecure` from share links is honoured; don't use it in production.

## Native dependencies

| Component | License |
| --- | --- |
| [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | MIT |
| [Xray-core](https://github.com/XTLS/Xray-core) | MPL-2.0 |
