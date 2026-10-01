// Template for the Packet Tunnel Network Extension target.
//
// 1. Add a "Network Extension" target (Packet Tunnel Provider) to your app.
// 2. Link VpnLib.xcframework (./gradlew :vpnlib:assembleVpnLibXCFramework)
//    and VpnCore.xcframework (native/build-ios.sh) into the extension.
// 3. Enable the "Network Extensions → Packet Tunnel" capability on the app and
//    the extension, plus a shared App Group if you share data between them.
// 4. Set NSExtensionPrincipalClass to $(PRODUCT_MODULE_NAME).PacketTunnelProvider.

import NetworkExtension
import VpnLib

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var engine = PacketTunnelEngine(provider: self)
    private var pathObservation: NSKeyValueObservation?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        pathObservation = observe(\.defaultPath, options: [.new]) { [weak self] _, _ in
            self?.engine.networkPathChanged()
        }
        engine.startTunnel(options: options) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pathObservation = nil
        engine.stopTunnel {
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        engine.handleAppMessage(message: messageData) { data in
            completionHandler?(data)
        }
    }
}
