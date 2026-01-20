#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle errors and cleanup resources
void handle_error(vpx_codec_ctx_t *codec, vpx_image_t *img) {
    if (codec) vpx_codec_destroy(codec);
    if (img) vpx_img_free(img);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_dec_cfg_t dec_cfg = {0};
    vpx_codec_stream_info_t stream_info;
    vpx_image_t *img = nullptr;
    vpx_codec_err_t res;

    // Initialize the decoder context
    res = vpx_codec_dec_init_ver(&codec, vpx_codec_vp8_dx(), &dec_cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        handle_error(&codec, nullptr);
        return 0;
    }

    // Get stream info
    memset(&stream_info, 0, sizeof(stream_info));
    stream_info.sz = sizeof(stream_info);
    res = vpx_codec_get_stream_info(&codec, &stream_info);
    if (res != VPX_CODEC_OK) {
        handle_error(&codec, nullptr);
        return 0;
    }

    // Allocate image buffer
    img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, stream_info.w, stream_info.h, 16);
    if (!img) {
        handle_error(&codec, nullptr);
        return 0;
    }

    // Decode the input data
    res = vpx_codec_decode(&codec, data, size, nullptr, 0);
    if (res != VPX_CODEC_OK) {
        handle_error(&codec, img);
        return 0;
    }

    // Cleanup
    vpx_codec_destroy(&codec);
    vpx_img_free(img);

    return 0;
}
