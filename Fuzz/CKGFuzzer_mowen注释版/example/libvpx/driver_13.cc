#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle frame buffer allocation
static int get_frame_buffer(void *user_priv, size_t min_size, vpx_codec_frame_buffer_t *fb) {
    // Cast the result of malloc to uint8_t* to match the type expected by fb->data
    fb->data = (uint8_t *)malloc(min_size);
    if (!fb->data) return -1;
    fb->size = min_size;
    return 0;
}

// Function to handle frame buffer release
static int release_frame_buffer(void *user_priv, vpx_codec_frame_buffer_t *fb) {
    free(fb->data);
    return 0;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize codec context
    vpx_codec_ctx_t codec;
    vpx_codec_err_t res;
    vpx_codec_stream_info_t stream_info;
    vpx_codec_iter_t iter = NULL;
    const vpx_image_t *img; // Use const vpx_image_t* to match the return type of vpx_codec_get_frame and vpx_codec_get_preview_frame

    // Initialize codec context
    memset(&codec, 0, sizeof(codec));
    res = vpx_codec_dec_init(&codec, vpx_codec_vp8_dx(), NULL, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(&codec, get_frame_buffer, release_frame_buffer, NULL);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Register put slice callback
    res = vpx_codec_register_put_slice_cb(&codec, NULL, NULL);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Register put frame callback
    res = vpx_codec_register_put_frame_cb(&codec, NULL, NULL);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Get stream info
    memset(&stream_info, 0, sizeof(stream_info));
    res = vpx_codec_get_stream_info(&codec, &stream_info);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Decode the input data
    res = vpx_codec_decode(&codec, data, size, NULL, 0);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Get the first frame
    img = vpx_codec_get_frame(&codec, &iter);
    if (img) {
        // Process the frame if needed
    }

    // Get the preview frame
    img = vpx_codec_get_preview_frame(&codec);
    if (img) {
        // Process the preview frame if needed
    }

    // Clean up
    vpx_codec_destroy(&codec);
    return 0;
}
