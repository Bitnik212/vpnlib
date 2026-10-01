/*
 * JNI bindings for io.github.bitnik212.vpnlib.android.internal.NativeCore.
 * Compiled only for GOOS=android (file name suffix).
 */
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <android/log.h>

#include "_cgo_export.h"

#define JNI_FN(name) Java_io_github_bitnik212_vpnlib_android_internal_NativeCore_##name

static JavaVM *g_vm;
static pthread_mutex_t g_protector_lock = PTHREAD_MUTEX_INITIALIZER;
static jobject g_protector;
static jmethodID g_protect_method;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

static void android_log(int32_t level, const char *tag, const char *message) {
    int priority;
    switch (level) {
        case 0: priority = ANDROID_LOG_DEBUG; break;
        case 1: priority = ANDROID_LOG_INFO; break;
        case 2: priority = ANDROID_LOG_WARN; break;
        default: priority = ANDROID_LOG_ERROR; break;
    }
    __android_log_write(priority, tag, message);
}

/* Called from Go threads: attach to the VM for the duration of the call. */
static int32_t android_protect(int32_t fd) {
    JNIEnv *env = NULL;
    int attached = 0;
    jboolean ok = JNI_FALSE;

    if ((*g_vm)->GetEnv(g_vm, (void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) {
            return 0;
        }
        attached = 1;
    }

    pthread_mutex_lock(&g_protector_lock);
    jobject protector = g_protector != NULL ? (*env)->NewLocalRef(env, g_protector) : NULL;
    jmethodID method = g_protect_method;
    pthread_mutex_unlock(&g_protector_lock);

    if (protector == NULL) {
        ok = JNI_TRUE; /* protector removed while a call was in flight */
    } else {
        ok = (*env)->CallBooleanMethod(env, protector, method, (jint) fd);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            ok = JNI_FALSE;
        }
        (*env)->DeleteLocalRef(env, protector);
    }

    if (attached) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
    return ok ? 1 : 0;
}

static jstring take_string(JNIEnv *env, char *value) {
    if (value == NULL) {
        return NULL;
    }
    jstring result = (*env)->NewStringUTF(env, value);
    vpncoreFree(value);
    return result;
}

JNIEXPORT void JNICALL JNI_FN(nativeInit)(JNIEnv *env, jobject thiz) {
    (void) env;
    (void) thiz;
    vpncoreSetLogger(android_log);
}

JNIEXPORT jstring JNICALL JNI_FN(version)(JNIEnv *env, jobject thiz) {
    (void) thiz;
    return take_string(env, vpncoreVersion());
}

JNIEXPORT jstring JNICALL JNI_FN(lastError)(JNIEnv *env, jobject thiz) {
    (void) thiz;
    return take_string(env, vpncoreLastError());
}

JNIEXPORT void JNICALL JNI_FN(setProtector)(JNIEnv *env, jobject thiz, jobject protector) {
    (void) thiz;
    jobject global = NULL;
    jmethodID method = NULL;
    if (protector != NULL) {
        jclass cls = (*env)->GetObjectClass(env, protector);
        method = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
        (*env)->DeleteLocalRef(env, cls);
        if (method == NULL) {
            return; /* NoSuchMethodError is pending */
        }
        global = (*env)->NewGlobalRef(env, protector);
    }

    pthread_mutex_lock(&g_protector_lock);
    jobject previous = g_protector;
    g_protector = global;
    g_protect_method = method;
    pthread_mutex_unlock(&g_protector_lock);

    if (previous != NULL) {
        (*env)->DeleteGlobalRef(env, previous);
    }
    vpncoreSetProtector(global != NULL ? android_protect : NULL);
}

JNIEXPORT void JNICALL JNI_FN(setDnsServers)(JNIEnv *env, jobject thiz, jstring servers) {
    (void) thiz;
    const char *value = (*env)->GetStringUTFChars(env, servers, NULL);
    if (value == NULL) {
        return;
    }
    vpncoreSetDnsServers((char *) value);
    (*env)->ReleaseStringUTFChars(env, servers, value);
}

JNIEXPORT jint JNICALL JNI_FN(awgTurnOn)(JNIEnv *env, jobject thiz, jint tun_fd, jstring settings) {
    (void) thiz;
    const char *value = (*env)->GetStringUTFChars(env, settings, NULL);
    if (value == NULL) {
        return -1;
    }
    jint handle = vpncoreAwgTurnOn(tun_fd, (char *) value);
    (*env)->ReleaseStringUTFChars(env, settings, value);
    return handle;
}

JNIEXPORT void JNICALL JNI_FN(awgTurnOff)(JNIEnv *env, jobject thiz, jint handle) {
    (void) env;
    (void) thiz;
    vpncoreAwgTurnOff(handle);
}

JNIEXPORT jstring JNICALL JNI_FN(awgGetConfig)(JNIEnv *env, jobject thiz, jint handle) {
    (void) thiz;
    return take_string(env, vpncoreAwgGetConfig(handle));
}

JNIEXPORT void JNICALL JNI_FN(awgBumpSockets)(JNIEnv *env, jobject thiz, jint handle) {
    (void) env;
    (void) thiz;
    vpncoreAwgBumpSockets(handle);
}

JNIEXPORT jint JNICALL JNI_FN(xrayStart)(JNIEnv *env, jobject thiz, jint tun_fd, jstring config) {
    (void) thiz;
    const char *value = (*env)->GetStringUTFChars(env, config, NULL);
    if (value == NULL) {
        return -1;
    }
    jint handle = vpncoreXrayStart(tun_fd, (char *) value);
    (*env)->ReleaseStringUTFChars(env, config, value);
    return handle;
}

JNIEXPORT void JNICALL JNI_FN(xrayStop)(JNIEnv *env, jobject thiz, jint handle) {
    (void) env;
    (void) thiz;
    vpncoreXrayStop(handle);
}

JNIEXPORT jstring JNICALL JNI_FN(xrayGetStats)(JNIEnv *env, jobject thiz, jint handle) {
    (void) thiz;
    return take_string(env, vpncoreXrayGetStats(handle));
}
