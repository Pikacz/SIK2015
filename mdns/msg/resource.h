#ifndef MDNS_MSG_RESOURCE
#define MDNS_MSG_RESOURCE

#include <stdint.h>
#include "limits.h"

struct __dns_resource {
  char NAME[DNS_R_NAME_MAX_LENGTH + 2];
  uint16_t TYPE;
  uint16_t CLASS;
  uint32_t TTL;
  uint16_t RDLENGTH;
  char RDATA[DNS_R_DATA_MAX_LENGTH];
  char * msg;
};

typedef struct __dns_resource dns_resource_t;

int resource_send_format(dns_resource_t * resource, char * buff);
int resource_from_network(dns_resource_t * resource, char * buff, int max_size,
                          char* full_msg);

int is_rPTR(dns_resource_t * resource);
void set_rPTR(dns_resource_t * resource);

int is_rA(dns_resource_t * resource);
void set_rA(dns_resource_t * resource);

#endif
