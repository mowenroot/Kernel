#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str) {
        memcpy(str, data, size);
        str[size] = '\0';
    }
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
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(vpx_codec_ctx_t) + sizeof(vpx_codec_dec_cfg_t) + sizeof(vpx_codec_stream_info_t)) {
        return 0;
    }

    // Initialize variables
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_dec_cfg_t dec_cfg;
    vpx_codec_stream_info_t stream_info;
    vpx_image_t* img = nullptr;
    char* fuzz_str = nullptr;

    // Initialize codec context and configuration
    memset(&codec_ctx, 0, sizeof(codec_ctx));
    memset(&dec_cfg, 0, sizeof(dec_cfg));
    memset(&stream_info, 0, sizeof(stream_info));

    // Convert fuzz input to a string
    fuzz_str = fuzzInputToString(data, size);
    if (!fuzz_str) {
        return 0;
    }

    // Initialize the decoder
    vpx_codec_err_t res = vpx_codec_dec_init_ver(&codec_ctx, vpx_codec_vp8_dx(), &dec_cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        safeFree(fuzz_str);
        return 0;
    }

    // Set frame buffer functions
    res = vpx_codec_set_frame_buffer_functions(&codec_ctx, nullptr, nullptr, nullptr);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_str);
        return 0;
    }

    // Get stream information
    res = vpx_codec_get_stream_info(&codec_ctx, &stream_info);
    if (res != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_str);
        return 0;
    }

    // Allocate image buffer
    img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, stream_info.w, stream_info.h, 16);
    if (!img) {
        vpx_codec_destroy(&codec_ctx);
        safeFree(fuzz_str);
        return 0;
    }

    // Retrieve detailed error information
    const char* error_detail = vpx_codec_error_detail(&codec_ctx);
    if (error_detail) {
        // Handle error detail if needed
    }

    // Clean up
    vpx_img_free(img);
    vpx_codec_destroy(&codec_ctx);
    safeFree(fuzz_str);

    return 0;
}
