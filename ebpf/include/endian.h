#pragma once

#define htons __builtin_bswap16
#define htonl __builtin_bswap32
#define ntohs __builtin_bswap16
#define ntohl __builtin_bswap32
