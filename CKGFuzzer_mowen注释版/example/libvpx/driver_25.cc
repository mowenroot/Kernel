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
        exit(1);
    }
    return ptr;
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (src == NULL || dest == NULL) {
        fprintf(stderr, "Invalid memory address for memcpy\n");
        exit(1);
    }
    memcpy(dest, src, n);
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
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_rational_t) + sizeof(vpx_codec_ctx_t)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_rational_t dsf;
    vpx_codec_iface_t* iface = vpx_codec_vp8_cx();
    vpx_codec_err_t res;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t* pkt;

    // Initialize the encoding configuration with default values
    res = vpx_codec_enc_config_default(iface, &enc_cfg, 0);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to get default encoding configuration: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Set up the down-sampling factor
    dsf.num = data[0];
    dsf.den = data[1];

    // Initialize the codec context for multi-resolution encoding
    res = vpx_codec_enc_init_multi_ver(&codec_ctx, iface, &enc_cfg, 1, 0, &dsf, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize multi-resolution encoder: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(&codec_ctx, NULL, NULL, NULL);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to set frame buffer functions: %s\n", vpx_codec_err_to_string(res));
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Create a dummy image for encoding
    vpx_image_t img;
    memset(&img, 0, sizeof(img));
    img.w = enc_cfg.g_w;
    img.h = enc_cfg.g_h;
    img.fmt = VPX_IMG_FMT_I420;
    img.d_w = enc_cfg.g_w;
    img.d_h = enc_cfg.g_h;
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.planes[0] = (uint8_t*)safe_malloc(img.w * img.h);
    img.planes[1] = (uint8_t*)safe_malloc(img.w * img.h / 4);
    img.planes[2] = (uint8_t*)safe_malloc(img.w * img.h / 4);
    img.stride[0] = img.w;
    img.stride[1] = img.w / 2;
    img.stride[2] = img.w / 2;

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to encode image: %s\n", vpx_codec_err_to_string(res));
        vpx_codec_destroy(&codec_ctx);
        safe_free(img.planes[0]);
        safe_free(img.planes[1]);
        safe_free(img.planes[2]);
        return 0;
    }

    // Retrieve and process the encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame data
        }
    }

    // Clean up
    vpx_codec_destroy(&codec_ctx);
    safe_free(img.planes[0]);
    safe_free(img.planes[1]);
    safe_free(img.planes[2]);

    return 0;
}
