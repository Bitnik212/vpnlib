#ifndef VPNCORE_CALLBACKS_H
#define VPNCORE_CALLBACKS_H

#include <stddef.h>
#include <stdint.h>

typedef void (*vpncore_log_fn)(int32_t level, const char *tag, const char *message);
typedef int32_t (*vpncore_protect_fn)(int32_t fd);

void vpncore_invoke_log(vpncore_log_fn fn, int32_t level, const char *tag, const char *message);
int32_t vpncore_invoke_protect(vpncore_protect_fn fn, int32_t fd);

#endif
