#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added this include to resolve 'stderr'

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set a rectangular region
int safe_set_rect(vpx_image_t* img, unsigned int x, unsigned int y, unsigned int w, unsigned int h) {
    if (x + w > img->w || y + h > img->h) {
        return -1;
    }
    return vpx_img_set_rect(img, x, y, w, h);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be meaningful
    if (size < sizeof(vpx_codec_enc_cfg_t) + sizeof(vpx_image_t) + 16) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t img;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_err_t res;

    // Initialize the encoder configuration
    memset(&cfg, 0, sizeof(cfg));
    cfg.g_w = 640;
    cfg.g_h = 480;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = 1000;

    // Initialize the codec
    res = vpx_codec_enc_init_ver(&codec, vpx_codec_vp8_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize codec: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Initialize the image
    memset(&img, 0, sizeof(img));
    img.w = 640;
    img.h = 480;
    img.fmt = VPX_IMG_FMT_I420;
    img.img_data = (uint8_t*)safe_malloc(img.w * img.h * 3 / 2);
    img.img_data_owner = 1;
    img.self_allocd = 0;
    img.bps = 12;
    img.stride[VPX_PLANE_Y] = img.w;
    img.stride[VPX_PLANE_U] = img.w / 2;
    img.stride[VPX_PLANE_V] = img.w / 2;

    // Set the rectangular region
    unsigned int x = data[0];
    unsigned int y = data[1];
    unsigned int w = data[2];
    unsigned int h = data[3];
    if (safe_set_rect(&img, x, y, w, h) != 0) {
        fprintf(stderr, "Failed to set rectangular region\n");
        vpx_img_free(&img);
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Encode the image
    res = vpx_codec_encode(&codec, &img, 0, 1, 0, VPX_DL_REALTIME);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to encode image: %s\n", vpx_codec_err_to_string(res));
        vpx_img_free(&img);
        vpx_codec_destroy(&codec);
        return 0;
    }

    // Retrieve and process the encoded data
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the encoded frame data
            // For example, you could write it to a buffer or file
        }
    }

    // Clean up
    vpx_img_free(&img);
    vpx_codec_destroy(&codec);

    return 0;
}
