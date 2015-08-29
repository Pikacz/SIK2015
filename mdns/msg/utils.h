#ifndef MDNS_MSG_UTILS
#define MDNS_MSG_UTILS

#include <stdint.h>

int unit16_to_send(uint16_t num, char * buff);

int unit32_to_send(uint32_t num, char * buff);

uint16_t get_uint16_t(char * buff);

uint32_t get_uint32_t(char * buff);

#endif
