#include <stdlib.h>

#include "msg.h"


void init_msg(dns_msg_t * msg) {
  init_header(&(msg->header));

  msg->questions = NULL;
  msg->answers = NULL;
  msg->authorities = NULL;
  msg->additionals = NULL;
}


void clean_msg(dns_msg_t * msg) {
  init_header(&(msg->header));

  free(msg->questions);
  msg->questions = NULL;

  free(msg->answers);
  msg->answers = NULL;

  free(msg->authorities);
  msg->authorities = NULL;

  free(msg->additionals);
  msg->additionals = NULL;
}

int send_format_msg(dns_msg_t * msg, char * buffer) {
  int size = 0, tmp;
  uint16_t i, ii;

  tmp = header_send_format(&(msg->header), buffer);
  buffer += tmp;
  size += tmp;

  ii = get_QDCOUNT(&(msg->header));
  for (i = 0; i < ii; ++i) {
    tmp = question_send_format(&((msg->questions)[i]), buffer);
    buffer += tmp;
    size += tmp;
  }

  ii = get_ANCOUNT(&(msg->header));
  for (i = 0; i < ii; ++i) {
    tmp = resource_send_format(&((msg->answers)[i]), buffer);
    buffer += tmp;
    size += tmp;
  }

  ii = get_NSCOUNT(&(msg->header));
  for (i = 0; i < ii; ++i) {
    tmp = resource_send_format(&((msg->authorities)[i]), buffer);
    buffer += tmp;
    size += tmp;
  }

  ii = get_ARCOUNT(&(msg->header));
  for (i = 0; i < ii; ++i) {
    tmp = resource_send_format(&((msg->additionals)[i]), buffer);
    buffer += tmp;
    size += tmp;
  }

  return size;
}


int message_from_network(dns_msg_t * msg, char * buff, int max_size) {
  char * tmp_buff = buff;
  uint16_t i;
  int tmp;
  tmp = header_from_network(&(msg->header), buff, max_size);
  if (tmp < 0)
    return -1;
  max_size -= tmp;
  buff += tmp;

  msg->questions = (dns_question_t *)
    malloc(sizeof(dns_question_t) * get_QDCOUNT(&(msg->header)));
  msg->answers = (dns_resource_t *)
    malloc(sizeof(dns_resource_t) * get_ANCOUNT(&(msg->header)));
  msg->authorities = (dns_resource_t *)
    malloc(sizeof(dns_resource_t) * get_NSCOUNT(&(msg->header)));
  msg->additionals = (dns_resource_t *)
    malloc(sizeof(dns_resource_t) * get_ARCOUNT(&(msg->header)));

  for(i = 0; i < get_QDCOUNT(&(msg->header)); ++i) {
    tmp = question_from_network(msg->questions + i, buff, max_size);
    if(tmp < 0)
      return -1;
    buff += tmp;
    max_size -= tmp;
  }

  for(i = 0; i < get_ANCOUNT(&(msg->header)); ++i) {
    tmp = resource_from_network(msg->answers + i, buff, max_size);
    if(tmp < 0)
      return -1;
    buff += tmp;
  }

  for(i = 0; i < get_NSCOUNT(&(msg->header)); ++i) {
    tmp = resource_from_network(msg->authorities + i, buff, max_size);
    if(tmp < 0)
      return -1;
    buff += tmp;
  }

  for(i = 0; i < get_ARCOUNT(&(msg->header)); ++i) {
    tmp = resource_from_network(msg->additionals + i, buff, max_size);
    if(tmp < 0)
      return -1;
    buff += tmp;
  }

  return buff - tmp_buff;
}
