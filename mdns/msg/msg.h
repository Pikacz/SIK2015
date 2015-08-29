#ifndef MDNS_MSG
#define MDNS_MSG

#include "header.h"
#include "question.h"
#include "resource.h"

struct __dns_msg {
  dns_header_t header;
  uint32_t max_q_length, max_an_length, max_au_length, max_ad_length;
  dns_question_t * questions;
  dns_resource_t * answers;
  dns_resource_t * authorities;
  dns_resource_t * additionals;

};

typedef struct __dns_msg dns_msg_t;

void init_msg(dns_msg_t * msg);

void clean_msg(dns_msg_t * msg);

void send_format(dns_msg_t * msg, char * buffer);

#endif
