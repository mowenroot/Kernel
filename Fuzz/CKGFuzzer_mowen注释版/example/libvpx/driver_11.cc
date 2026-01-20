#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h> // Include this header for stderr

// Function to handle errors and print them
void handle_error(vpx_codec_ctx_t *ctx) {
    const char *error_str = vpx_codec_error(ctx);
    if (error_str) {
        fprintf(stderr, "Error: %s\n", error_str);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize codec context
    vpx_codec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Initialize stream info
    vpx_codec_stream_info_t si;
    memset(&si, 0, sizeof(si));
    si.sz = sizeof(vpx_codec_stream_info_t);

    // Initialize iterator for frame retrieval
    vpx_codec_iter_t iter = NULL;

    // Initialize codec interface
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
    if (!iface) {
        return 0; // Failed to get codec interface
    }

    // Initialize codec
    vpx_codec_err_t res = vpx_codec_dec_init(&ctx, iface, NULL, 0);
    if (res != VPX_CODEC_OK) {
        handle_error(&ctx);
        return 0; // Failed to initialize codec
    }

    // Peek stream info
    res = vpx_codec_peek_stream_info(iface, data, size, &si);
    if (res != VPX_CODEC_OK) {
        handle_error(&ctx);
        vpx_codec_destroy(&ctx);
        return 0; // Failed to peek stream info
    }

    // Decode the stream
    res = vpx_codec_decode(&ctx, data, size, NULL, 0);
    if (res != VPX_CODEC_OK) {
        handle_error(&ctx);
        vpx_codec_destroy(&ctx);
        return 0; // Failed to decode stream
    }

    // Get stream info
    res = vpx_codec_get_stream_info(&ctx, &si);
    if (res != VPX_CODEC_OK) {
        handle_error(&ctx);
        vpx_codec_destroy(&ctx);
        return 0; // Failed to get stream info
    }

    // Retrieve frames
    vpx_image_t *img;
    while ((img = vpx_codec_get_frame(&ctx, &iter)) != NULL) {
        // Process the frame if needed
    }

    // Clean up
    vpx_codec_destroy(&ctx);

    return 0;
}
