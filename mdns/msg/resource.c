#include <netinet/in.h>

#include "resource.h"
#include "utils.h"


int resource_send_format(dns_resource_t * resource, char * buff) {
  int tmp, i = 0, j = 0;

  char c = (resource->NAME)[j], cc;
  buff[i] = c;
  j++;
  i++;

  while(c) {
    for(cc = 0; cc < c; ++cc) {
      buff[i] = resource->NAME[j];
      j++;
      i++;
    }

    c = buff[i] = resource->NAME[j];
    ++i;
    ++j;
  }

  tmp = unit16_to_send(resource->TYPE, buff + i);
  i += tmp;

  tmp = unit16_to_send(resource->CLASS, buff + i);
  i += tmp;

  tmp = unit32_to_send(resource->TTL, buff + i);
  i += tmp;

  tmp = unit16_to_send(resource->RDLENGTH, buff + i);
  i += tmp;

  for (j = 0; j < resource->RDLENGTH; ++j) {
    buff[i] = (resource->RDATA)[j];
    ++i;
  }

  return i;
}


int resource_from_network(dns_resource_t * resource, char * buff, int max_size) {
  char * c = buff;
  int tmp;
  tmp = get_NAME_from_net(resource->NAME, buff, max_size);
  if (tmp < 0)
    return -1;
  max_size -= tmp;
  buff += tmp;

  if(max_size < 2)
    return -1;
  resource->TYPE = get_uint16_t(buff);
  buff += 2;
  max_size -= 2;

  if(max_size < 2)
    return -1;
  resource->CLASS = get_uint16_t(buff);
  buff += 2;
  max_size -= 2;

  if(max_size < 4)
    return -1;
  resource->TTL = get_uint32_t(buff);
  buff += 4;
  max_size -= 4;

  if(max_size < 2)
    return -1;
  resource->RDLENGTH = get_uint16_t(buff);
  buff += 2;
  max_size -= 2;

  int i;
  for (i = 0; i < resource->RDLENGTH; ++i) {
    if(max_size == 0)
      return -1;
    resource->RDATA[i] = *buff;
    buff++;
    max_size--;
  }
  return buff - c;
}
