#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added this include to resolve 'stderr' undeclared identifier

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (s && n > 0) {
        memset(s, c, n);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is valid
    if (!data || size == 0) {
        return 0;
    }

    // Initialize codec context
    vpx_codec_ctx_t codec_ctx;
    safe_memset(&codec_ctx, 0, sizeof(codec_ctx));

    // Initialize stream info
    vpx_codec_stream_info_t stream_info;
    safe_memset(&stream_info, 0, sizeof(stream_info));

    // Initialize image
    vpx_image_t img;
    safe_memset(&img, 0, sizeof(img));

    // Initialize iterator
    vpx_codec_iter_t iter = NULL;

    // Allocate memory for the image
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420; // Example format
    unsigned int img_width = 640; // Example width
    unsigned int img_height = 480; // Example height
    unsigned int img_align = 16; // Example alignment

    vpx_image_t* img_ptr = vpx_img_alloc(&img, img_fmt, img_width, img_height, img_align);
    if (!img_ptr) {
        fprintf(stderr, "Failed to allocate image\n");
        return 0;
    }

    // Set frame buffer functions
    vpx_get_frame_buffer_cb_fn_t get_frame_buffer_cb = NULL;
    vpx_release_frame_buffer_cb_fn_t release_frame_buffer_cb = NULL;
    void* cb_priv = NULL;

    vpx_codec_err_t set_fb_res = vpx_codec_set_frame_buffer_functions(
        &codec_ctx, get_frame_buffer_cb, release_frame_buffer_cb, cb_priv);
    if (set_fb_res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to set frame buffer functions: %d\n", set_fb_res);
        vpx_img_free(img_ptr);
        return 0;
    }

    // Register put frame callback
    vpx_codec_put_frame_cb_fn_t put_frame_cb = NULL;
    void* user_priv = NULL;

    vpx_codec_err_t reg_put_frame_res = vpx_codec_register_put_frame_cb(
        &codec_ctx, put_frame_cb, user_priv);
    if (reg_put_frame_res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to register put frame callback: %d\n", reg_put_frame_res);
        vpx_img_free(img_ptr);
        return 0;
    }

    // Get stream info
    vpx_codec_err_t get_si_res = vpx_codec_get_stream_info(&codec_ctx, &stream_info);
    if (get_si_res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to get stream info: %d\n", get_si_res);
        vpx_img_free(img_ptr);
        return 0;
    }

    // Get encoded data packets
    const vpx_codec_cx_pkt_t* pkt = vpx_codec_get_cx_data(&codec_ctx, &iter);
    if (!pkt) {
        fprintf(stderr, "Failed to get encoded data packets\n");
        vpx_img_free(img_ptr);
        return 0;
    }

    // Free allocated resources
    vpx_img_free(img_ptr);

    return 0;
}
