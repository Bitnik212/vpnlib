#include "callbacks.h"

void vpncore_invoke_log(vpncore_log_fn fn, int32_t level, const char *tag, const char *message) {
    if (fn != NULL) {
        fn(level, tag, message);
    }
}

int32_t vpncore_invoke_protect(vpncore_protect_fn fn, int32_t fd) {
    if (fn == NULL) {
        return 1;
    }
    return fn(fd);
}
