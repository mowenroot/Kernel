#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str) {
        memcpy(str, data, size);
        str[size] = '\0';
    }
    return str;
}

// Function to free the allocated string
void freeFuzzInputString(char* str) {
    if (str) {
        free(str);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t *img = NULL;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt = NULL;
    vpx_codec_err_t res;

    // Convert fuzz input to a string
    char* fuzz_input = fuzzInputToString(data, size);
    if (!fuzz_input) {
        return 0; // Early exit if memory allocation fails
    }

    // Initialize the encoder configuration
    res = vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg, 0);
    if (res != VPX_CODEC_OK) {
        freeFuzzInputString(fuzz_input);
        return 0; // Early exit if configuration initialization fails
    }

    // Initialize the encoder context
    res = vpx_codec_enc_init_ver(&codec_ctx, vpx_codec_vp8_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        freeFuzzInputString(fuzz_input);
        return 0; // Early exit if encoder initialization fails
    }

    // Allocate memory for the image
    img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 16);
    if (!img) {
        vpx_codec_destroy(&codec_ctx);
        freeFuzzInputString(fuzz_input);
        return 0; // Early exit if image allocation fails
    }

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec_ctx);
        freeFuzzInputString(fuzz_input);
        return 0; // Early exit if encoding fails
    }

    // Retrieve the encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        // Process the packet if needed
    }

    // Free allocated resources
    vpx_img_free(img);
    vpx_codec_destroy(&codec_ctx);
    freeFuzzInputString(fuzz_input);

    return 0; // Return 0 to indicate success
}
