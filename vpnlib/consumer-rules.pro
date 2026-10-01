# JNI entry points of libvpncore.so
-keep class io.github.bitnik212.vpnlib.android.internal.NativeCore {
    native <methods>;
}
# Invoked from native code through JNI (protect(int) -> boolean)
-keep interface io.github.bitnik212.vpnlib.android.SocketProtector { *; }
-keepclassmembers class * implements io.github.bitnik212.vpnlib.android.SocketProtector {
    boolean protect(int);
}
