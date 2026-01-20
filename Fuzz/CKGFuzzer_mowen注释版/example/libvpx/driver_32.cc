#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data from fuzz input
void* safe_alloc_and_copy(const uint8_t* src, size_t size) {
    void* dest = malloc(size);
    if (dest) {
        safe_copy(dest, src, size);
    }
    return dest;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_image_t) + sizeof(vpx_codec_ctx_t)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_image_t* img = nullptr;
    vpx_codec_err_t res;

    // Initialize the encoder configuration with default values
    res = vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &enc_cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Initialize the encoder context
    res = vpx_codec_enc_init_ver(&codec_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Allocate memory for the image
    img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, enc_cfg.g_w, enc_cfg.g_h, 16);
    if (!img) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Copy fuzz input data to the image buffer
    size_t img_size = img->d_w * img->d_h * 3 / 2; // I420 format size
    if (size >= img_size) {
        safe_copy(img->img_data, data, img_size);
    }

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Clean up
    vpx_img_free(img);
    vpx_codec_destroy(&codec_ctx);

    return 0;
}
