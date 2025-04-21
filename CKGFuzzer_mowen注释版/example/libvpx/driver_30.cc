#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle errors and cleanup resources
void handle_error(vpx_codec_ctx_t *ctx, vpx_image_t *img) {
    if (ctx) {
        vpx_codec_destroy(ctx);
        free(ctx);
    }
    if (img) {
        vpx_img_free(img);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t *ctx = (vpx_codec_ctx_t *)malloc(sizeof(vpx_codec_ctx_t));
    if (!ctx) {
        return 0; // Allocation failure
    }
    memset(ctx, 0, sizeof(vpx_codec_ctx_t));

    vpx_image_t *img = NULL;
    vpx_codec_iface_t *iface = vpx_codec_vp8_dx();
    vpx_codec_dec_cfg_t cfg = {0};
    vpx_codec_flags_t flags = 0;

    // Initialize the decoder
    vpx_codec_err_t res = vpx_codec_dec_init_ver(ctx, iface, &cfg, flags, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        handle_error(ctx, img);
        return 0;
    }

    // Allocate image buffer
    img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, 640, 480, 16);
    if (!img) {
        handle_error(ctx, img);
        return 0;
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(ctx, NULL, NULL, NULL);
    if (res != VPX_CODEC_OK) {
        handle_error(ctx, img);
        return 0;
    }

    // Decode the input data
    res = vpx_codec_decode(ctx, data, size, NULL, 0);
    if (res != VPX_CODEC_OK) {
        handle_error(ctx, img);
        return 0;
    }

    // Cleanup
    vpx_codec_destroy(ctx);
    vpx_img_free(img);
    free(ctx);

    return 0;
}
