#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a vpx_codec_ctx_t
vpx_codec_ctx_t* safe_vpx_codec_ctx_alloc() {
    vpx_codec_ctx_t* ctx = (vpx_codec_ctx_t*)malloc(sizeof(vpx_codec_ctx_t));
    if (!ctx) return nullptr;
    memset(ctx, 0, sizeof(vpx_codec_ctx_t));
    return ctx;
}

// Function to safely allocate memory for a vpx_codec_iface_t
vpx_codec_iface_t* safe_vpx_codec_iface_alloc() {
    // vpx_codec_iface_t is a pointer to a const struct, so we don't need to allocate memory for it
    return nullptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size == 0 || data == nullptr) return 0;

    // Initialize variables
    vpx_codec_ctx_t* ctx = nullptr;
    vpx_codec_iface_t* iface = nullptr;
    char* iface_name = nullptr;
    char* version_str = nullptr;
    char* version_extra_str = nullptr;
    char* error_str = nullptr;
    int version = 0;

    // Allocate memory for the context and interface
    ctx = safe_vpx_codec_ctx_alloc();
    // iface is not allocated since it's a pointer to a const struct
    if (!ctx) goto cleanup;

    // Retrieve and print the version information
    version = vpx_codec_version();
    version_str = safe_strndup((const uint8_t*)vpx_codec_version_str(), strlen(vpx_codec_version_str()));
    version_extra_str = safe_strndup((const uint8_t*)vpx_codec_version_extra_str(), strlen(vpx_codec_version_extra_str()));
    if (!version_str || !version_extra_str) goto cleanup;

    // Retrieve and print the interface name
    // iface is not allocated, so we use a valid interface directly
    iface = vpx_codec_vp8_dx(); // Example: using VP8 decoder interface
    iface_name = safe_strndup((const uint8_t*)vpx_codec_iface_name(iface), strlen(vpx_codec_iface_name(iface)));
    if (!iface_name) goto cleanup;

    // Retrieve and print the error message
    error_str = safe_strndup((const uint8_t*)vpx_codec_error(ctx), strlen(vpx_codec_error(ctx)));
    if (!error_str) goto cleanup;

    // Cleanup allocated resources
cleanup:
    free(ctx);
    // iface is not allocated, so no need to free it
    free(iface_name);
    free(version_str);
    free(version_extra_str);
    free(error_str);

    return 0;
}
