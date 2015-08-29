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
};

typedef struct __dns_resource dns_resource_t;


#endif
