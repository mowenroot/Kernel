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
    // Ensure we have enough data for basic operations
    if (size < sizeof(int) * 3 + sizeof(vpx_codec_enc_cfg_t)) return 0;

    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t* cfg = safe_enc_cfg_dup(data, sizeof(vpx_codec_enc_cfg_t));
    if (!cfg) return 0;

    int* width = safe_intdup(data + sizeof(vpx_codec_enc_cfg_t), sizeof(int));
    int* height = safe_intdup(data + sizeof(vpx_codec_enc_cfg_t) + sizeof(int), sizeof(int));
    int* flags = safe_intdup(data + sizeof(vpx_codec_enc_cfg_t) + 2 * sizeof(int), sizeof(int));

    if (!width || !height || !flags) {
        free(cfg);
        free(width);
        free(height);
        free(flags);
        return 0;
    }

    // Initialize the codec
    vpx_codec_err_t res = vpx_codec_enc_init_ver(&codec, vpx_codec_vp8_cx(), cfg, *flags, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        free(cfg);
        free(width);
        free(height);
        free(flags);
        return 0;
    }

    // Allocate an image
    vpx_image_t* img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, *width, *height, 16);
    if (!img) {
        vpx_codec_destroy(&codec);
        free(cfg);
        free(width);
        free(height);
        free(flags);
        return 0;
    }

    // Encode the image
    res = vpx_codec_encode(&codec, img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec);
        free(cfg);
        free(width);
        free(height);
        free(flags);
        return 0;
    }

    // Retrieve encoded data
    vpx_codec_iter_t iter = nullptr;
    const vpx_codec_cx_pkt_t* pkt;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
        // Process the packet if needed
    }

    // Clean up
    vpx_img_free(img);
    vpx_codec_destroy(&codec);
    free(cfg);
    free(width);
    free(height);
    free(flags);

    return 0;
}
