#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>
#include <memory>

// Function to safely convert fuzz input to cmsFloat64Number
cmsFloat64Number safe_convert_to_float(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return 0.0; // Return a default value if not enough data
    }
    cmsFloat64Number value;
    memcpy(&value, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return value;
}

// Function to safely convert fuzz input to cmsCIELab
void safe_convert_to_lab(const uint8_t* data, size_t size, size_t& offset, cmsCIELab& lab) {
    lab.L = safe_convert_to_float(data, size, offset);
    lab.a = safe_convert_to_float(data, size, offset);
    lab.b = safe_convert_to_float(data, size, offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least two cmsCIELab structures and some parameters
    if (size < 2 * sizeof(cmsCIELab) + 3 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    size_t offset = 0;

    // Initialize two cmsCIELab structures from fuzz input
    cmsCIELab lab1, lab2;
    safe_convert_to_lab(data, size, offset, lab1);
    safe_convert_to_lab(data, size, offset, lab2);

    // Initialize parameters for cmsCIE2000DeltaE
    cmsFloat64Number Kl = safe_convert_to_float(data, size, offset);
    cmsFloat64Number Kc = safe_convert_to_float(data, size, offset);
    cmsFloat64Number Kh = safe_convert_to_float(data, size, offset);

    // Call each API at least once
    cmsFloat64Number result_cie2000 = cmsCIE2000DeltaE(&lab1, &lab2, Kl, Kc, Kh);
    cmsFloat64Number result_cmc = cmsCMCdeltaE(&lab1, &lab2, 1.0, 1.0);
    cmsFloat64Number result_bfd = cmsBFDdeltaE(&lab1, &lab2);

    cmsCIELCh lch1, lch2;
    cmsLab2LCh(&lch1, &lab1);
    cmsLab2LCh(&lch2, &lab2);

    cmsFloat64Number result_cie94 = cmsCIE94DeltaE(&lab1, &lab2);
    cmsFloat64Number result_deltaE = cmsDeltaE(&lab1, &lab2);

    // Ensure all results are valid (not NaN or inf)
    if (std::isnan(result_cie2000) || std::isinf(result_cie2000) ||
        std::isnan(result_cmc) || std::isinf(result_cmc) ||
        std::isnan(result_bfd) || std::isinf(result_bfd) ||
        std::isnan(result_cie94) || std::isinf(result_cie94) ||
        std::isnan(result_deltaE) || std::isinf(result_deltaE)) {
        return 0;
    }

    return 0;
}
