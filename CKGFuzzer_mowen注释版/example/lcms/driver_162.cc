#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Define a simple structure to represent a plugin
struct SimplePlugin {
    uint32_t Magic;
    uint32_t ExpectedVersion;
    uint32_t Type;
    struct SimplePlugin* Next;
};

// Function to create a SimplePlugin from fuzz input
SimplePlugin* createPluginFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(SimplePlugin)) {
        return nullptr;
    }

    SimplePlugin* plugin = (SimplePlugin*)malloc(sizeof(SimplePlugin));
    if (!plugin) {
        return nullptr;
    }

    memcpy(plugin, data, sizeof(SimplePlugin));
    plugin->Next = nullptr;

    return plugin;
}

// Function to free a SimplePlugin
void freePlugin(SimplePlugin* plugin) {
    if (plugin) {
        free(plugin);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Create a plugin from the fuzz input
    SimplePlugin* plugin = createPluginFromInput(data, size);
    if (!plugin) {
        cmsDeleteContext(context);
        return 0;
    }

    // Register the plugin using cmsPluginTHR
    cmsBool result = cmsPluginTHR(context, plugin);
    if (!result) {
        freePlugin(plugin);
        cmsDeleteContext(context);
        return 0;
    }

    // Unregister the plugin using cmsUnregisterPluginsTHR
    cmsUnregisterPluginsTHR(context);

    // Free the plugin
    freePlugin(plugin);

    // Delete the context
    cmsDeleteContext(context);

    return 0;
}
