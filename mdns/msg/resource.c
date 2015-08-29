#include "resource.h"
#include "utils.h"


int resource_send_format(dns_resource_t * resource, char * buff) {
  int size = 0, tmp;
  char *it = resource->NAME;

  while(*it) {
    *buff = *it;
    ++it;
    ++buff;
    ++size;
  }
  tmp = unit16_to_send(resource->TYPE, buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send(resource->CLASS, buff);
  size += tmp;
  buff += tmp;

  tmp = unit32_to_send(resource->TTL, buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send(resource->RDLENGTH, buff);
  size += tmp;
  buff += tmp;

  it = resource->RDATA;
  for (tmp = 0; tmp < resource->RDLENGTH; ++tmp) {
    *buff = *it;
    ++it;
    ++buff;
    ++size;
  }
  
  return size;
}


void resource_from_network(dns_resource_t * resource, char * buff);
