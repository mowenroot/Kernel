#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle memory allocation failures
void handle_memory_failure() {
    fprintf(stderr, "Memory allocation failed\n");
    abort();
}

// Function to handle invalid input size
void handle_invalid_input_size() {
    fprintf(stderr, "Invalid input size\n");
    abort();
}

// Custom log error handler function
void customLogErrorHandler(cmsContext ContextID, cmsUInt32Number ErrorCode, const char *Text) {
    fprintf(stderr, "Custom Error Handler: %s\n", Text);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(cmsFloat64Number) + sizeof(cmsUInt16Number) * cmsMAXCHANNELS) {
        handle_invalid_input_size();
        return 0;
    }

    // Create a CMS context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        handle_memory_failure();
        return 0;
    }

    // Set the adaptation state
    cmsFloat64Number adaptationState = *reinterpret_cast<const cmsFloat64Number*>(data);
    cmsSetAdaptationStateTHR(context, adaptationState);

    // Set the log error handler
    cmsSetLogErrorHandlerTHR(context, customLogErrorHandler);

    // Unregister plugins
    cmsUnregisterPluginsTHR(context);

    // Set alarm codes
    const cmsUInt16Number *alarmCodes = reinterpret_cast<const cmsUInt16Number*>(data + sizeof(cmsFloat64Number));
    cmsSetAlarmCodesTHR(context, alarmCodes);

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}
