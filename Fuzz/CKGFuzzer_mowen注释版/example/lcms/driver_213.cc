#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>
#include <memory>

// Function to safely extract a double from the fuzz input
bool safe_extract_double(const uint8_t*& data, size_t& size, cmsFloat64Number& value) {
    if (size < sizeof(cmsFloat64Number)) return false;
    memcpy(&value, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    return true;
}

// Function to safely extract a cmsCIELab structure from the fuzz input
bool safe_extract_cmsCIELab(const uint8_t*& data, size_t& size, cmsCIELab& lab) {
    if (size < 3 * sizeof(cmsFloat64Number)) return false;
    memcpy(&lab.L, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    memcpy(&lab.a, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    memcpy(&lab.b, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= 3 * sizeof(cmsFloat64Number);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least two cmsCIELab structures and some parameters
    if (size < 6 * sizeof(cmsFloat64Number)) return 0;

    // Extract two cmsCIELab structures
    cmsCIELab lab1, lab2;
    if (!safe_extract_cmsCIELab(data, size, lab1) || !safe_extract_cmsCIELab(data, size, lab2)) {
        return 0;
    }

    // Extract parameters for cmsCIE2000DeltaE
    cmsFloat64Number Kl, Kc, Kh;
    if (!safe_extract_double(data, size, Kl) || !safe_extract_double(data, size, Kc) || !safe_extract_double(data, size, Kh)) {
        return 0;
    }

    // Call each API at least once
    cmsFloat64Number deltaE2000 = cmsCIE2000DeltaE(&lab1, &lab2, Kl, Kc, Kh);
    cmsFloat64Number bfdDeltaE = cmsBFDdeltaE(&lab1, &lab2);

    cmsCIELCh lch1, lch2;
    cmsLab2LCh(&lch1, &lab1);
    cmsLab2LCh(&lch2, &lab2);

    cmsCIELab lab1_from_lch, lab2_from_lch;
    cmsLCh2Lab(&lab1_from_lch, &lch1);
    cmsLCh2Lab(&lab2_from_lch, &lch2);

    cmsFloat64Number deltaE94 = cmsCIE94DeltaE(&lab1, &lab2);
    cmsFloat64Number deltaE = cmsDeltaE(&lab1, &lab2);

    // Ensure all results are valid (not NaN or Inf)
    if (std::isnan(deltaE2000) || std::isinf(deltaE2000) ||
        std::isnan(bfdDeltaE) || std::isinf(bfdDeltaE) ||
        std::isnan(deltaE94) || std::isinf(deltaE94) ||
        std::isnan(deltaE) || std::isinf(deltaE)) {
        return 0;
    }

    return 0;
}
