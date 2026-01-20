#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr

// Function to get a frame buffer
extern "C" int get_frame_buffer(void *user_priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
    // Cast the result of malloc to uint8_t* to match the type expected by fb->data
    fb->data = (uint8_t *)malloc(min_size);
    if (!fb->data) return -1;
    fb->size = min_size;
    return 0;
}

// Function to release a frame buffer
extern "C" int release_frame_buffer(void *user_priv, vpx_codec_frame_buffer_t *fb) {
    free(fb->data);
    return 0;  // Return 0 to match the expected signature
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_dec_cfg_t cfg = {0};
    vpx_codec_stream_info_t stream_info = {0};
    vpx_codec_err_t res;

    // Initialize the decoder context
    res = vpx_codec_dec_init_ver(&codec, vpx_codec_vp8_dx(), &cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize decoder: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(&codec, get_frame_buffer, release_frame_buffer, NULL);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to set frame buffer functions: %s\n", vpx_codec_err_to_string(res));
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Get stream info
    res = vpx_codec_get_stream_info(&codec, &stream_info);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to get stream info: %s\n", vpx_codec_err_to_string(res));
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Free resources
    vpx_codec_destroy(&codec);

    return 0;
}
