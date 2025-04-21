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

// Function to safely allocate memory for an integer
int* safe_intdup(const uint8_t* data, size_t size) {
    if (size < sizeof(int)) return nullptr;
    int* num = (int*)malloc(sizeof(int));
    if (!num) return nullptr;
    memcpy(num, data, sizeof(int));
    return num;
}

// Function to safely allocate memory for a vpx_codec_enc_cfg_t structure
vpx_codec_enc_cfg_t* safe_enc_cfg_dup(const uint8_t* data, size_t size) {
    if (size < sizeof(vpx_codec_enc_cfg_t)) return nullptr;
    vpx_codec_enc_cfg_t* cfg = (vpx_codec_enc_cfg_t*)malloc(sizeof(vpx_codec_enc_cfg_t));
    if (!cfg) return nullptr;
    memcpy(cfg, data, sizeof(vpx_codec_enc_cfg_t));
    return cfg;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t img;
    vpx_codec_err_t res;
    vpx_codec_iter_t iter = nullptr;
    const vpx_codec_cx_pkt_t *pkt;

    // Ensure we have enough data for basic operations
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(int) + sizeof(vpx_img_fmt_t)) {
        return 0;
    }

    // Extract configuration from fuzz input
    vpx_codec_enc_cfg_t* cfg_ptr = safe_enc_cfg_dup(data, sizeof(vpx_codec_enc_cfg_t));
    if (!cfg_ptr) return 0;
    cfg = *cfg_ptr;
    free(cfg_ptr);

    // Extract image format and dimensions
    vpx_img_fmt_t fmt = *(vpx_img_fmt_t*)(data + sizeof(vpx_codec_enc_cfg_t));
    int width = *(int*)(data + sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_img_fmt_t));
    int height = *(int*)(data + sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_img_fmt_t) + sizeof(int));

    // Allocate image structure
    if (!vpx_img_alloc(&img, fmt, width, height, 16)) {
        return 0;
    }

    // Initialize encoder
    res = vpx_codec_enc_init_ver(&codec, &vpx_codec_vp8_cx_algo, &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(&img);
        return 0;
    }

    // Set encoder configuration
    res = vpx_codec_enc_config_set(&codec, &cfg);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        vpx_img_free(&img);
        return 0;
    }

    // Encode a frame
    res = vpx_codec_encode(&codec, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        vpx_img_free(&img);
        return 0;
    }

    // Retrieve encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the packet if needed
        }
    }

    // Clean up
    vpx_codec_destroy(&codec);
    vpx_img_free(&img);

    return 0;
}
