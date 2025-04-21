#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added to include the header for stderr

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (src && dest && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be meaningful
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_image_t)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t img;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_err_t res;
    const vpx_image_t *preview_frame; // Declare preview_frame here

    // Initialize the codec configuration structure
    memset(&cfg, 0, sizeof(cfg));
    cfg.g_w = 640; // Example width
    cfg.g_h = 480; // Example height
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;

    // Initialize the image structure
    memset(&img, 0, sizeof(img));
    img.w = 640; // Example width
    img.h = 480; // Example height
    img.fmt = VPX_IMG_FMT_I420;
    img.d_w = 640; // Example width
    img.d_h = 480; // Example height
    img.planes[0] = (uint8_t*)safe_malloc(640 * 480); // Y plane
    img.planes[1] = (uint8_t*)safe_malloc(640 * 480 / 4); // U plane
    img.planes[2] = (uint8_t*)safe_malloc(640 * 480 / 4); // V plane
    img.stride[0] = 640;
    img.stride[1] = 640 / 2;
    img.stride[2] = 640 / 2;

    // Initialize the codec
    res = vpx_codec_enc_init_ver(&codec, vpx_codec_vp8_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec: %s\n", vpx_codec_err_to_string(res));
        goto cleanup;
    }

    // Encode a frame
    res = vpx_codec_encode(&codec, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to encode frame: %s\n", vpx_codec_err_to_string(res));
        goto cleanup;
    }

    // Get the encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame data
        }
    }

    // Get the preview frame
    preview_frame = vpx_codec_get_preview_frame(&codec);
    if (preview_frame) {
        // Process the preview frame
    }

cleanup:
    // Destroy the codec
    vpx_codec_destroy(&codec);

    // Free allocated memory
    safe_free(img.planes[0]);
    safe_free(img.planes[1]);
    safe_free(img.planes[2]);

    return 0;
}
