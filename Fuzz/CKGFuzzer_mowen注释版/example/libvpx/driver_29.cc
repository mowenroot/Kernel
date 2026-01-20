#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle frame output
void put_frame_cb(void *user_priv, const vpx_image_t *img) {
    // This function can be extended to handle the frame as needed
    (void)user_priv;
    (void)img;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize codec context
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));

    // Initialize decoder configuration
    vpx_codec_dec_cfg_t dec_cfg;
    memset(&dec_cfg, 0, sizeof(dec_cfg));

    // Initialize flags
    vpx_codec_flags_t flags = 0;

    // Initialize iterator
    vpx_codec_iter_t iter = NULL;

    // Initialize user data for callbacks
    void *user_priv = NULL;

    // Initialize image pointer
    vpx_image_t *img = NULL;

    // Initialize error code
    vpx_codec_err_t res;

    // Ensure data size is within a reasonable limit
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize decoder
    res = vpx_codec_dec_init_ver(&codec, vpx_codec_vp8_dx(), &dec_cfg, flags, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Register frame callback
    res = vpx_codec_register_put_frame_cb(&codec, put_frame_cb, user_priv);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Decode the input data
    res = vpx_codec_decode(&codec, data, size, user_priv, 0);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Get the decoded frame
    img = vpx_codec_get_frame(&codec, &iter);
    if (img == NULL) {
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Clean up
    vpx_codec_destroy(&codec);

    return 0;
}
