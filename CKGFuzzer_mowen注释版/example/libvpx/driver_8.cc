#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header for stderr

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    vpx_codec_ctx_t enc_ctx;
    vpx_codec_ctx_t dec_ctx;
    vpx_codec_enc_cfg_t enc_cfg;
    vpx_codec_dec_cfg_t dec_cfg;
    vpx_codec_stream_info_t stream_info;
    vpx_codec_err_t res;

    // Initialize encoder configuration
    if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &enc_cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Initialize decoder configuration
    memset(&dec_cfg, 0, sizeof(dec_cfg));

    // Initialize encoder context
    res = vpx_codec_enc_init_ver(&enc_ctx, vpx_codec_vp8_cx(), &enc_cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        return 0;
    }

    // Initialize decoder context
    res = vpx_codec_dec_init_ver(&dec_ctx, vpx_codec_vp8_dx(), &dec_cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&enc_ctx);
        return 0;
    }

    // Encode data
    vpx_image_t img;
    memset(&img, 0, sizeof(img));
    img.w = 640;
    img.h = 480;
    img.fmt = VPX_IMG_FMT_I420;
    img.d_w = 640;
    img.d_h = 480;
    img.x_chroma_shift = 1;
    img.y_chroma_shift = 1;
    img.planes[0] = (uint8_t*)safe_malloc(img.w * img.h);
    img.planes[1] = (uint8_t*)safe_malloc(img.w * img.h / 4);
    img.planes[2] = (uint8_t*)safe_malloc(img.w * img.h / 4);
    img.stride[0] = img.w;
    img.stride[1] = img.w / 2;
    img.stride[2] = img.w / 2;

    safe_memcpy(img.planes[0], data, img.w * img.h);
    safe_memcpy(img.planes[1], data + img.w * img.h, img.w * img.h / 4);
    safe_memcpy(img.planes[2], data + img.w * img.h + img.w * img.h / 4, img.w * img.h / 4);

    res = vpx_codec_encode(&enc_ctx, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&enc_ctx);
        vpx_codec_destroy(&dec_ctx);
        safe_free(img.planes[0]);
        safe_free(img.planes[1]);
        safe_free(img.planes[2]);
        return 0;
    }

    // Decode data
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    while ((pkt = vpx_codec_get_cx_data(&enc_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            res = vpx_codec_decode(&dec_ctx, (uint8_t*)pkt->data.frame.buf, pkt->data.frame.sz, NULL, 0);
            if (res != VPX_CODEC_OK) {
                vpx_codec_destroy(&enc_ctx);
                vpx_codec_destroy(&dec_ctx);
                safe_free(img.planes[0]);
                safe_free(img.planes[1]);
                safe_free(img.planes[2]);
                return 0;
            }
        }
    }

    // Get stream info
    memset(&stream_info, 0, sizeof(stream_info));
    res = vpx_codec_get_stream_info(&dec_ctx, &stream_info);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&enc_ctx);
        vpx_codec_destroy(&dec_ctx);
        safe_free(img.planes[0]);
        safe_free(img.planes[1]);
        safe_free(img.planes[2]);
        return 0;
    }

    // Clean up
    vpx_codec_destroy(&enc_ctx);
    vpx_codec_destroy(&dec_ctx);
    safe_free(img.planes[0]);
    safe_free(img.planes[1]);
    safe_free(img.planes[2]);

    return 0;
}
