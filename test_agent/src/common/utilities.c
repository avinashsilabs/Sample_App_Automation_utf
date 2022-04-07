#include "utilities.h"
#include "rsi_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define IPV4_FORMAT "%u.%u.%u.%u"

static const char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                       'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                       'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                       'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                       'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                       'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                       'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                       '4', '5', '6', '7', '8', '9', '+', '/' };
static const char decoding_table[256] = {1, 0, -1164473928, 32589, 9, 0, 0, 0, 1, 0, -1164215832, 32589, 1813535700, 32766, -1164473928, 32589, -1164215832, 32589, -1164213000, 32589, 0, 0, 1813746104, 32766, -1164254529, 32589, 1, 0, -1, 0, 1813535700, 32766, -1166481520, 32589, -1164476416, 32589, 1813536192, 32766, 1813535680, 32766, 1813535936, 32766, -1164337989, 62, -1164220615, 32589, -1164330036, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1164405376, 32589, -1164215832, 32589, -1164349676, 32589, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 32589, -1164404204, 32589, -1164405568, 32589, -1164218296, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 2343, 0, 0, -1164213872, 32589, -8, -1, -1164300432, 32589, 1813536544, 32766, -1164388437, 32589, 0, 0, 0, 0, -1686704940, -21863, 0, 0, 4, 0, 1, 0, -1164212480, 32589, -1164470976, 32589, -1164213920, 32589, 1813536001, 32766, -1164215832, 32589, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1813746200, 32766, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 1, 0, 61765110, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 576, 832, 896, 896, 960, 1472, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 2496, 0, 0, 256, 64, 0, 64, 512, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1686704192, 21862, 15775231, 0};
static const int mod_table[] = { 0, 2, 1 };


uint32_t str_to_ipv4(const char* string)
{
    uint32_t temp[4];
    int nchars = -1;
    static const char str_to_ip_fmt[] = IPV4_FORMAT"%n";

    if (sscanf(string, str_to_ip_fmt, (unsigned int*)&temp[0], (unsigned int*)&temp[1], (unsigned int*)&temp[2], (unsigned int*)&temp[3], &nchars) != 4)
    {
        return 0;
    }
    // Check for extra characters not read in
    else if (*(string + nchars) != '\0')
    {
        return 0;
    }
    else if (temp[0] > 255 || temp[1] > 255 || temp[2] > 255 || temp[3] > 255)
    {
        return 0;
    }

    return (uint32_t)temp[3] << 24 | temp[2] << 16 | temp[1] << 8 | temp[0];
}


void print_status(int32_t status)
{
    switch (status) {
    case RSI_ERROR_NONE: printf("success\r\n"); break;
    case RSI_ERROR_PKT_ALLOCATION_FAILURE: printf("Error: packet allocation fail\r\n"); break;
    case RSI_ERROR_WLAN_CMD_IN_PROGRESS:   printf("Error: WLAN command in progress\r\n"); break;
    case RSI_ERROR_INSUFFICIENT_BUFFER:  printf("Error: memory allocation failure\r\n"); break;
    default:
        printf("status: 0x%lX\r\n", status);
        break;
    }
}

char* base64_encode(const uint8_t* data,
    uint32_t input_length)
{
    uint32_t output_length = 4 * ((input_length + 2) / 3);

    char* encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (uint32_t i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = 0;
    return encoded_data;
}

uint8_t* base64_decode(const char* data, uint32_t input_length, uint32_t *output_length)
{
    if (input_length % 4 != 0) return NULL;
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (uint32_t i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(size_t)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(size_t)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(size_t)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(size_t)data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    return decoded_data;
}
