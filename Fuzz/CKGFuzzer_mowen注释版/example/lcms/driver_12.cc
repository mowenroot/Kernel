#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>
#include <memory>

// Helper function to safely extract a float from the fuzz input
bool safe_extract_float(const uint8_t*& data, size_t& size, cmsFloat64Number& value) {
    if (size < sizeof(cmsFloat64Number)) return false;
    memcpy(&value, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    return true;
}

// Helper function to safely extract a CIELab structure from the fuzz input
bool safe_extract_CIELab(const uint8_t*& data, size_t& size, cmsCIELab& lab) {
    if (size < sizeof(cmsCIELab)) return false;
    memcpy(&lab, data, sizeof(cmsCIELab));
    data += sizeof(cmsCIELab);
    size -= sizeof(cmsCIELab);
    return true;
}

// Helper function to safely extract a CIELCh structure from the fuzz input
bool safe_extract_CIELCh(const uint8_t*& data, size_t& size, cmsCIELCh& lch) {
    if (size < sizeof(cmsCIELCh)) return false;
    memcpy(&lch, data, sizeof(cmsCIELCh));
    data += sizeof(cmsCIELCh);
    size -= sizeof(cmsCIELCh);
    return true;
}

// Helper function to safely extract a CIEXYZ structure from the fuzz input
bool safe_extract_CIEXYZ(const uint8_t*& data, size_t& size, cmsCIEXYZ& xyz) {
    if (size < sizeof(cmsCIEXYZ)) return false;
    memcpy(&xyz, data, sizeof(cmsCIEXYZ));
    data += sizeof(cmsCIEXYZ);
    size -= sizeof(cmsCIEXYZ);
    return true;
}

// Helper function to safely extract a cmsJCh structure from the fuzz input
bool safe_extract_cmsJCh(const uint8_t*& data, size_t& size, cmsJCh& jch) {
    if (size < sizeof(cmsJCh)) return false;
    memcpy(&jch, data, sizeof(cmsJCh));
    data += sizeof(cmsJCh);
    size -= sizeof(cmsJCh);
    return true;
}

// Helper function to safely extract a cmsViewingConditions structure from the fuzz input
bool safe_extract_cmsViewingConditions(const uint8_t*& data, size_t& size, cmsViewingConditions& vc) {
    if (size < sizeof(cmsViewingConditions)) return false;
    memcpy(&vc, data, sizeof(cmsViewingConditions));
    data += sizeof(cmsViewingConditions);
    size -= sizeof(cmsViewingConditions);
    return true;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsCIELab lab1, lab2;
    cmsCIELCh lch1, lch2;
    cmsCIEXYZ xyz1, xyz2;
    cmsJCh jch1, jch2;
    cmsViewingConditions vc;
    cmsFloat64Number l, c, deltaE;
    cmsHANDLE hModel = nullptr;

    // Ensure we have enough data for all required inputs
    if (size < (sizeof(cmsCIELab) * 2 + sizeof(cmsFloat64Number) * 2 + sizeof(cmsViewingConditions))) {
        return 0;
    }

    // Extract inputs from fuzz data
    if (!safe_extract_CIELab(data, size, lab1) ||
        !safe_extract_CIELab(data, size, lab2) ||
        !safe_extract_float(data, size, l) ||
        !safe_extract_float(data, size, c) ||
        !safe_extract_cmsViewingConditions(data, size, vc)) {
        return 0;
    }

    // Initialize CIECAM02 model
    hModel = cmsCIECAM02Init(nullptr, &vc);
    if (!hModel) {
        return 0;
    }

    // Convert Lab to LCh
    cmsLab2LCh(&lch1, &lab1);
    cmsLab2LCh(&lch2, &lab2);

    // Convert LCh to Lab
    cmsLCh2Lab(&lab1, &lch1);
    cmsLCh2Lab(&lab2, &lch2);

    // Calculate CMC delta E
    deltaE = cmsCMCdeltaE(&lab1, &lab2, l, c);

    // Convert XYZ to JCh using CIECAM02
    cmsCIECAM02Forward(hModel, &xyz1, &jch1);

    // Convert JCh to XYZ using CIECAM02
    cmsCIECAM02Reverse(hModel, &jch1, &xyz2);

    // Clean up
    if (hModel) {
        cmsCIECAM02Done(hModel); // Use cmsCIECAM02Done instead of cmsFree
    }

    return 0;
}
