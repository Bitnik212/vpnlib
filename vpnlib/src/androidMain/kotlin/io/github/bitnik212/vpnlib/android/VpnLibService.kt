package io.github.bitnik212.vpnlib.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import io.github.bitnik212.vpnlib.android.internal.ProfileStore
import io.github.bitnik212.vpnlib.android.internal.VpnRuntime
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.tunnel.TunnelPlan
import io.github.bitnik212.vpnlib.tunnel.TunnelPlanner
import io.github.bitnik212.vpnlib.tunnel.TunnelSession
import io.github.bitnik212.vpnlib.tunnel.TunnelState
import io.github.bitnik212.vpnlib.tunnel.TunnelStatistics
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * VpnService running WireGuard, AmneziaWG and Xray tunnels.
 *
 * Declared in the library manifest, so it works out of the box. Subclass it
 * to customize the notification ([createNotification]) or the interface
 * ([configureBuilder]); declare the subclass in your manifest with
 * `android:permission="android.permission.BIND_VPN_SERVICE"`,
 * `android:foregroundServiceType="systemExempted"` and the
 * `android.net.VpnService` intent filter, and pass it to [AndroidVpnController].
 *
 * Always-on VPN restarts the last connected profile.
 */
public open class VpnLibService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private var startJob: Job? = null

    private var session: TunnelSession? = null
    private var tunnelFd: ParcelFileDescriptor? = null

    @Volatile
    private var currentProfile: VpnProfile? = null

    override fun onCreate() {
        super.onCreate()
        VpnRuntime.activeService = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        val profile = intent?.getStringExtra(EXTRA_PROFILE)
            ?.let { json -> runCatching { VpnProfile.fromJson(json) }.getOrNull() }
            ?: ProfileStore.load(this) // always-on start or restart without extras
        if (profile == null) {
            VpnRuntime.state.value = TunnelState.Error(null, "No VPN profile to start")
            stopSelf()
            return START_NOT_STICKY
        }
        currentProfile = profile
        startForegroundCompat(createNotification(TunnelState.Connecting(profile.id), profile))
        connect(profile)
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked the permission.
        disconnect()
    }

    override fun onDestroy() {
        startJob?.cancel()
        stopTunnel()
        if (VpnRuntime.state.value !is TunnelState.Error) VpnRuntime.state.value = TunnelState.Disconnected
        if (VpnRuntime.activeService === this) VpnRuntime.activeService = null
        scope.cancel()
        super.onDestroy()
    }

    /** Counters of the running tunnel. */
    public fun statistics(): TunnelStatistics? = session?.statistics()

    internal fun connect(profile: VpnProfile) {
        startJob?.cancel()
        startJob = scope.launch {
            lock.withLock {
                stopTunnel()
                startTunnel(profile)
            }
        }
    }

    internal fun disconnect() {
        startJob?.cancel()
        scope.launch {
            lock.withLock {
                VpnRuntime.state.value = TunnelState.Disconnecting(currentProfile?.id)
                stopTunnel()
                VpnRuntime.state.value = TunnelState.Disconnected
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private suspend fun startTunnel(profile: VpnProfile) {
        VpnRuntime.state.value = TunnelState.Connecting(profile.id)
        try {
            val connectivity = getSystemService(ConnectivityManager::class.java)
            val underlying = connectivity?.activeNetwork
            val plan = TunnelPlanner(AndroidHostResolver(underlying)).plan(profile)

            val builder = Builder()
            applyPlan(builder, plan)
            configureBuilder(builder, plan)
            val fd = builder.establish() ?: throw VpnException("VPN permission was not granted")
            tunnelFd = fd

            AndroidVpnCore.setProtector { socket -> protect(socket) }
            val systemDns = connectivity?.getLinkProperties(underlying)?.dnsServers
                ?.mapNotNull { it.hostAddress?.substringBefore('%') }
                .orEmpty()
            AndroidVpnCore.setDnsServers(systemDns.ifEmpty { plan.dnsServers })

            session = TunnelSession.start(AndroidVpnCore, plan, fd.fd)
            ProfileStore.save(this, profile)
            val connected = TunnelState.Connected(profile.id, System.currentTimeMillis())
            VpnRuntime.state.value = connected
            notify(createNotification(connected, profile))
        } catch (e: CancellationException) {
            stopTunnel()
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tunnel", e)
            stopTunnel()
            VpnRuntime.state.value = TunnelState.Error(profile.id, e.message ?: e.toString())
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun applyPlan(builder: Builder, plan: TunnelPlan) {
        builder.setSession(plan.sessionName)
        builder.setMtu(plan.mtu)
        plan.addresses.forEach { builder.addAddress(it.address.toString(), it.prefixLength) }
        plan.routes.forEach { builder.addRoute(it.address.toString(), it.prefixLength) }
        plan.dnsServers.forEach { builder.addDnsServer(it) }
        plan.searchDomains.forEach { builder.addSearchDomain(it) }
        try {
            if (plan.includedApplications.isNotEmpty()) {
                plan.includedApplications.forEach { builder.addAllowedApplication(it) }
            } else {
                plan.excludedApplications.forEach { builder.addDisallowedApplication(it) }
            }
        } catch (e: PackageManager.NameNotFoundException) {
            throw VpnException("Application not installed: ${e.message}", e)
        }
        if (plan.allowBypass) builder.allowBypass()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(plan.metered)
        configureIntent()?.let { builder.setConfigureIntent(it) }
    }

    private fun stopTunnel() {
        session?.stop()
        session = null
        tunnelFd?.let { runCatching { it.close() } }
        tunnelFd = null
        AndroidVpnCore.setProtector(null)
    }

    /** Hook to adjust the interface before it is established. */
    protected open fun configureBuilder(builder: Builder, plan: TunnelPlan) {}

    /** Activity opened from the system VPN settings and the notification. */
    protected open fun configureIntent(): PendingIntent? {
        val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return null
        return PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    /** Foreground notification; override for custom UI. */
    protected open fun createNotification(state: TunnelState, profile: VpnProfile?): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (manager?.getNotificationChannel(NOTIFICATION_CHANNEL) == null) {
                manager?.createNotificationChannel(
                    NotificationChannel(NOTIFICATION_CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW),
                )
            }
            Notification.Builder(this, NOTIFICATION_CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val text = when (state) {
            is TunnelState.Connected -> "Connected"
            is TunnelState.Connecting, is TunnelState.Reconnecting -> "Connecting…"
            is TunnelState.Error -> state.message
            else -> "Disconnected"
        }
        val icon = applicationInfo.icon.takeIf { it != 0 } ?: android.R.drawable.ic_dialog_info
        return builder
            .setSmallIcon(icon)
            .setContentTitle(profile?.name ?: "VPN")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(configureIntent())
            .build()
    }

    private fun notify(notification: Notification) {
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID, notification)
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    public companion object {
        public const val ACTION_CONNECT: String = "io.github.bitnik212.vpnlib.action.CONNECT"
        public const val ACTION_DISCONNECT: String = "io.github.bitnik212.vpnlib.action.DISCONNECT"
        public const val EXTRA_PROFILE: String = "io.github.bitnik212.vpnlib.extra.PROFILE"

        private const val TAG = "VpnLibService"
        private const val NOTIFICATION_ID = 0x7670
        private const val NOTIFICATION_CHANNEL = "vpnlib"
    }
}
