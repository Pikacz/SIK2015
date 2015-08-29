#include <stdlib.h>

#include "msg.h"


void init_msg(dns_msg_t * msg) {
  init_header(&(msg->header));
  msg->max_q_length = 4;
  msg->questions = (dns_question_t *)
                      malloc(msg->max_q_length * sizeof(dns_question_t));
  msg->max_an_length = 4;
  msg->answers = (dns_resource_t *)
                         malloc(msg->max_an_length * sizeof(dns_resource_t));
  msg->max_au_length = 4;
  msg->authorities = (dns_resource_t *)
                         malloc(msg->max_au_length * sizeof(dns_resource_t));
  msg->max_ad_length = 4;
  msg->additionals = (dns_resource_t *)
                         malloc(msg->max_ad_length * sizeof(dns_resource_t));
}


void clean_msg(dns_msg_t * msg) {
  init_header(&(msg->header));

  msg->max_q_length = 0;
  free(msg->questions);
  msg->questions = NULL;

  msg->max_an_length = 0;
  free(msg->answers);
  msg->answers = NULL;

  msg->max_au_length = 0;
  free(msg->authorities);
  msg->authorities = NULL;

  msg->max_ad_length = 0;
  free(msg->additionals);
  msg->additionals = NULL;
}

void send_format(dns_msg_t * msg, char * buffer) {
  
}
