#pragma once

#include <stdint.h>

// convert an IPv4 address string to a 32-bit integer
uint32_t str_to_ipv4(const char *string);

// print status output to console
void print_status(int32_t status);

// encode a buffer to a base64-encoded string.
// Note:  caller must call free on returned pointer
char* base64_encode(const uint8_t* binary_data, uint32_t length);

// decode buffer from a base64-encoded string
// Note:  caller must call free on returned pointer
uint8_t* base64_decode(const char* data, uint32_t input_length, uint32_t *output_length);
