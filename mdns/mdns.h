#ifndef MDNS
#define MDNS

#include "msg/msg.h"

void init_mdns();
int answer_A(dns_question_t * question, dns_resource_t * answer, uint32_t myip);
void ask_A(char * host_to_res, dns_question_t * question);
void ask_PTR(char * serv, dns_question_t * question);
#endif
