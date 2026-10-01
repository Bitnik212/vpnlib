// App-side usage example (SwiftUI / UIKit agnostic).

import VpnLib

final class VpnModel {
    // Bundle id of your Packet Tunnel extension target.
    private let controller = IosVpnController(providerBundleIdentifier: "com.example.app.tunnel")
    private var stateWatcher: Cancellable?

    func start() async throws {
        try await controller.load()
        stateWatcher = VpnControllerKt.watchState(controller) { state in
            print("VPN state: \(state)")
        }
    }

    func connect(wgQuickText: String) async throws {
        let config = WgQuickFormat.shared.parse(text: wgQuickText)
        let profile = VpnProfile(id: "home", name: "Home", config: config, options: TunnelOptions())
        try await controller.connect(profile: profile)
    }

    func connect(shareLink: String) async throws {
        let config = XrayConfig.companion.fromShareLink(link: shareLink)
        let profile = VpnProfile(id: "xray", name: "Xray", config: config, options: TunnelOptions())
        try await controller.connect(profile: profile)
    }
}
