#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate and copy a buffer from fuzz input
static unsigned char* safe_bufndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    unsigned char *buf = (unsigned char*)malloc(size);
    if (!buf) return NULL;
    memcpy(buf, data, size);
    return buf;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    ares_dns_record_t *dnsrec = NULL;
    unsigned char *query_buf = NULL;
    int query_len = 0;
    struct ares_soa_reply *soa_reply = NULL;
    struct hostent *ns_reply = NULL;
    struct ares_mx_reply *mx_reply = NULL;

    // Extract parameters from fuzz input
    unsigned short id = (unsigned short)((data[0] << 8) | data[1]);
    unsigned short flags = (unsigned short)((data[2] << 8) | data[3]);
    ares_dns_opcode_t opcode = (ares_dns_opcode_t)data[4];
    ares_dns_rcode_t rcode = (ares_dns_rcode_t)data[5];
    int dnsclass = (int)data[6];
    int type = (int)data[7];
    int rd = (int)data[8];
    size_t name_len = (size_t)data[9];
    size_t buf_len = (size_t)data[10];

    // Ensure name and buffer lengths are within bounds
    if (name_len + 11 > size || buf_len + 11 > size) return 0;

    // Create DNS record
    ares_status_t status = ares_dns_record_create(&dnsrec, id, flags, opcode, rcode);
    if (status != ARES_SUCCESS) goto cleanup;

    // Create query buffer
    char *name = safe_strndup(data + 11, name_len);
    if (!name) goto cleanup;

    status = ares_mkquery(name, dnsclass, type, id, rd, &query_buf, &query_len);
    if (status != ARES_SUCCESS) goto cleanup;

    // Parse SOA reply
    status = ares_parse_soa_reply(query_buf, query_len, &soa_reply);
    if (status != ARES_SUCCESS) goto cleanup;

    // Parse NS reply
    status = ares_parse_ns_reply(query_buf, query_len, &ns_reply);
    if (status != ARES_SUCCESS) goto cleanup;

    // Parse MX reply
    status = ares_parse_mx_reply(query_buf, query_len, &mx_reply);
    if (status != ARES_SUCCESS) goto cleanup;

cleanup:
    // Free allocated resources
    free(name);
    free(query_buf);
    ares_dns_record_destroy(dnsrec);
    ares_free_data(soa_reply);
    ares_free_hostent(ns_reply);
    ares_free_data(mx_reply);

    return 0;
}
