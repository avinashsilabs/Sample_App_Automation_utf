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
static char *decoding_table = NULL;
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

    // build decoding table
    decoding_table = malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;

    for (uint32_t i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    free(decoding_table);

    return decoded_data;
    


    
    free(decoding_table);
}
