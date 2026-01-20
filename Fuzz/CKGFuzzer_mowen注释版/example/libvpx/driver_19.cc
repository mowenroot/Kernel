#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(uint8_t *dest, const uint8_t *src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data from fuzz input
uint8_t* safe_alloc_and_copy(const uint8_t *data, size_t size) {
    if (data && size > 0) {
        uint8_t *buffer = (uint8_t*)malloc(size);
        if (buffer) {
            safe_copy(buffer, data, size);
            return buffer;
        }
    }
    return nullptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_image_t *img = nullptr;
    uint8_t *encoded_data = nullptr;
    size_t encoded_size = 0;
    vpx_codec_err_t res;

    // Initialize the encoder configuration
    if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &enc_cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Initialize the encoder context
    res = vpx_codec_enc_init_ver(&codec_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Allocate memory for the image
    img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, enc_cfg.g_w, enc_cfg.g_h, 16);
    if (!img) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Copy fuzz input data to the image buffer
    size_t img_size = img->w * img->h * 3 / 2; // I420 format size
    if (size > img_size) {
        size = img_size;
    }
    safe_copy(img->img_data, data, size);

    // Encode the image
    res = vpx_codec_encode(&codec_ctx, img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Get the encoded data
    vpx_codec_iter_t iter = nullptr;
    const vpx_codec_cx_pkt_t *pkt;
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != nullptr) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            encoded_data = (uint8_t*)malloc(pkt->data.frame.sz);
            if (encoded_data) {
                safe_copy(encoded_data, (uint8_t*)pkt->data.frame.buf, pkt->data.frame.sz);
                encoded_size = pkt->data.frame.sz;
            }
            break;
        }
    }

    // Decode the encoded data
    if (encoded_data && encoded_size > 0) {
        vpx_codec_ctx_t decoder_ctx;
        res = vpx_codec_dec_init(&decoder_ctx, vpx_codec_vp8_dx(), nullptr, 0);
        if (res == VPX_CODEC_OK) {
            res = vpx_codec_decode(&decoder_ctx, encoded_data, encoded_size, nullptr, 0);
            if (res != VPX_CODEC_OK) {
                vpx_codec_destroy(&decoder_ctx);
            }
        }
        vpx_codec_destroy(&decoder_ctx);
    }

    // Free allocated resources
    free(encoded_data);
    vpx_img_free(img);
    vpx_codec_destroy(&codec_ctx);

    return 0;
}
