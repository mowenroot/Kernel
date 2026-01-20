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

// Function to safely allocate memory for vpx_image_t
vpx_image_t* safe_vpx_img_alloc(const uint8_t* data, size_t size) {
    vpx_image_t* img = (vpx_image_t*)malloc(sizeof(vpx_image_t));
    if (!img) return nullptr;
    memset(img, 0, sizeof(vpx_image_t));
    // Initialize img fields based on data and size
    // This is a simplified example; actual initialization should be more thorough
    img->w = 640;
    img->h = 480;
    img->fmt = VPX_IMG_FMT_I420;
    img->d_w = img->w;
    img->d_h = img->h;
    img->planes[0] = (uint8_t*)data;
    img->planes[1] = img->planes[0] + size / 2;
    img->planes[2] = img->planes[1] + size / 4;
    img->stride[0] = img->w;
    img->stride[1] = img->w / 2;
    img->stride[2] = img->w / 2;
    return img;
}

// Function to safely allocate memory for vpx_codec_ctx_t
vpx_codec_ctx_t* safe_vpx_codec_ctx_alloc() {
    vpx_codec_ctx_t* ctx = (vpx_codec_ctx_t*)malloc(sizeof(vpx_codec_ctx_t));
    if (!ctx) return nullptr;
    memset(ctx, 0, sizeof(vpx_codec_ctx_t));
    return ctx;
}

// Function to safely allocate memory for vpx_codec_enc_cfg_t
vpx_codec_enc_cfg_t* safe_vpx_codec_enc_cfg_alloc() {
    vpx_codec_enc_cfg_t* cfg = (vpx_codec_enc_cfg_t*)malloc(sizeof(vpx_codec_enc_cfg_t));
    if (!cfg) return nullptr;
    memset(cfg, 0, sizeof(vpx_codec_enc_cfg_t));
    return cfg;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    vpx_codec_ctx_t* ctx = safe_vpx_codec_ctx_alloc();
    if (!ctx) return 0;

    vpx_codec_enc_cfg_t* cfg = safe_vpx_codec_enc_cfg_alloc();
    if (!cfg) {
        free(ctx);
        return 0;
    }

    vpx_image_t* img = safe_vpx_img_alloc(data, size);
    if (!img) {
        free(ctx);
        free(cfg);
        return 0;
    }

    // Get default configuration
    vpx_codec_err_t res = vpx_codec_enc_config_default(vpx_codec_vp8_cx(), cfg, 0);
    if (res != VPX_CODEC_OK) {
        free(ctx);
        free(cfg);
        free(img);
        return 0;
    }

    // Initialize the encoder
    res = vpx_codec_enc_init_ver(ctx, vpx_codec_vp8_cx(), cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        free(ctx);
        free(cfg);
        free(img);
        return 0;
    }

    // Set encoder configuration
    res = vpx_codec_enc_config_set(ctx, cfg);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(ctx);
        free(ctx);
        free(cfg);
        free(img);
        return 0;
    }

    // Encode the image
    res = vpx_codec_encode(ctx, img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(ctx);
        free(ctx);
        free(cfg);
        free(img);
        return 0;
    }

    // Get global headers
    vpx_fixed_buf_t* headers = vpx_codec_get_global_headers(ctx);
    if (headers) {
        // Process headers if needed
        free(headers->buf);
        free(headers);
    }

    // Clean up
    vpx_codec_destroy(ctx);
    free(ctx);
    free(cfg);
    free(img);

    return 0;
}
