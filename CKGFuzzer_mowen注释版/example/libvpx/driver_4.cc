#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added to include the declaration of stderr

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
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
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_dec_cfg_t dec_cfg;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    vpx_codec_err_t res;

    // Initialize the decoder configuration structure
    memset(&dec_cfg, 0, sizeof(dec_cfg));

    // Initialize the codec context
    res = vpx_codec_dec_init_ver(&codec_ctx, &vpx_codec_vp8_dx_algo, &dec_cfg, 0, VPX_DECODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize decoder: %s\n", vpx_codec_err_to_string(res));
        return 0;
    }

    // Decode the input data
    res = vpx_codec_decode(&codec_ctx, data, size, NULL, 0);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to decode data: %s\n", vpx_codec_err_to_string(res));
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }

    // Retrieve and process the decoded data packets
    while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Process the frame packet if needed
        }
    }

    // Destroy the codec context to free resources
    res = vpx_codec_destroy(&codec_ctx);
    if (res != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to destroy codec context: %s\n", vpx_codec_err_to_string(res));
    }

    return 0;
}
