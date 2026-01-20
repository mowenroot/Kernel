#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added this include to resolve 'stderr' undeclared identifier

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
    if (n > 0) {
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
    // Ensure the input data is large enough to be useful
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_image_t) + sizeof(vpx_codec_ctx_t)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t img;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_err_t res;

    // Initialize the codec configuration
    memset(&cfg, 0, sizeof(cfg));
    cfg.g_w = 640;
    cfg.g_h = 480;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = 1000;

    // Initialize the codec context
    res = vpx_codec_enc_init_ver(&codec, vpx_codec_vp8_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Initialize the image structure
    memset(&img, 0, sizeof(img));
    img.w = 640;
    img.h = 480;
    img.fmt = VPX_IMG_FMT_I420;
    img.d_w = 640;
    img.d_h = 480;
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.planes[0] = (uint8_t*)safe_malloc(640 * 480);
    img.planes[1] = (uint8_t*)safe_malloc(640 * 480 / 4);
    img.planes[2] = (uint8_t*)safe_malloc(640 * 480 / 4);
    img.stride[0] = 640;
    img.stride[1] = 640 / 2;
    img.stride[2] = 640 / 2;

    // Copy fuzz input data to image planes
    safe_memcpy(img.planes[0], data, 640 * 480);
    safe_memcpy(img.planes[1], data + 640 * 480, 640 * 480 / 4);
    safe_memcpy(img.planes[2], data + 640 * 480 + 640 * 480 / 4, 640 * 480 / 4);

    // Encode the image
    res = vpx_codec_encode(&codec, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to encode image: %s\n", vpx_codec_err_to_string(res));
        goto cleanup;
    }

    // Retrieve and process encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame data
        }
    }

    // Cleanup
cleanup:
    vpx_img_free(&img);
    vpx_codec_destroy(&codec);

    return 0;
}
