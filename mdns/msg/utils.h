#ifndef MDNS_MSG_UTILS
#define MDNS_MSG_UTILS

#include <stdint.h>
#include <stdio.h>

int unit16_to_send(uint16_t num, char * buff);

int unit32_to_send(uint32_t num, char * buff);

uint16_t get_uint16_t(char * buff);

uint32_t get_uint32_t(char * buff);

int get_NAME_from_net(char * dest, char * buff, int max_size, char * full_msg);

int domain_to_NAME(char * NAME, const char * domain);

int names_equal(char * n1, char * n2);

int fprintfname(FILE * f, char * name);

#endif
