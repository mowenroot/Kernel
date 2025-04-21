#include <stdio.h> // Add this line to include the declaration for stderr
#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (s && n > 0) {
        memset(s, c, n);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < 16) {
        return 0;
    }

    // Initialize codec context
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_image_t img;
    vpx_codec_err_t res;

    // Initialize codec configuration
    res = vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &enc_cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Set encoder configuration using fuzz input
    enc_cfg.g_w = data[0] % 1920 + 1; // Width between 1 and 1920
    enc_cfg.g_h = data[1] % 1080 + 1; // Height between 1 and 1080
    enc_cfg.g_timebase.num = data[2] % 1000 + 1; // Timebase numerator
    enc_cfg.g_timebase.den = data[3] % 1000 + 1; // Timebase denominator

    // Initialize codec context
    res = vpx_codec_enc_init(&codec_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Wrap image buffer using fuzz input
    unsigned int img_width = enc_cfg.g_w;
    unsigned int img_height = enc_cfg.g_h;
    unsigned int img_stride = img_width;
    unsigned char* img_data = (unsigned char*)safe_malloc(img_width * img_height * 3 / 2);
    safe_memset(img_data, 0, img_width * img_height * 3 / 2);

    vpx_img_wrap(&img, VPX_IMG_FMT_I420, img_width, img_height, img_stride, img_data);

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec_ctx);
        free(img_data);
        return 0;
    }

    // Retrieve encoded data
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame data if needed
        }
    }

    // Clean up
    vpx_img_free(&img);
    vpx_codec_destroy(&codec_ctx);
    free(img_data);

    return 0;
}
