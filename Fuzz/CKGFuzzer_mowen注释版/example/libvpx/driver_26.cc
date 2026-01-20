#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to free allocated memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_image_t img;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_err_t res;

    // Convert fuzz input to a string
    char* fuzz_input = fuzzInputToString(data, size);
    if (!fuzz_input) {
        return 0; // Early exit if memory allocation fails
    }

    // Initialize the encoder configuration
    res = vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &enc_cfg, 0);
    if (res != VPX_CODEC_OK) {
        safeFree(fuzz_input);
        return 0; // Early exit if configuration fails
    }

    // Initialize the encoder
    res = vpx_codec_enc_init_ver(&codec_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        safeFree(fuzz_input);
        return 0; // Early exit if initialization fails
    }

    // Allocate memory for the image
    if (!vpx_img_alloc(&img, VPX_IMG_FMT_I420, enc_cfg.g_w, enc_cfg.g_h, 16)) {
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_input);
        return 0; // Early exit if image allocation fails
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(&codec_ctx, NULL, NULL, NULL);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_input);
        return 0; // Early exit if setting frame buffer functions fails
    }

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(&img);
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_input);
        return 0; // Early exit if encoding fails
    }

    // Get the encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame packet
            // For fuzzing, we don't need to do anything with the packet data
        }
    }

    // Clean up
    vpx_img_free(&img);
    vpx_codec_destroy(&codec_ctx);
    safeFree(fuzz_input);

    return 0; // Return 0 to indicate success
}
