#ifndef MDNS_MSG_QUESTION
#define MDNS_MSG_QUESTION

#include <stdint.h>
#include "limits.h"

struct __dns_question {
  uint16_t QTYPE;
  uint16_t QCLASS;
  char QNAME[DNS_Q_QNAME_MAX_LENGTH + 2];
};

typedef struct __dns_question dns_question_t;

void set_QU(dns_question_t * question);

void set_QM(dns_question_t * question);

uint16_t is_QM(dns_question_t * question);

// domian == 'w' 'w' 'w' '.' 'a' '.' 'p' 'l' '\0'
// tj domain jest stringiem zakonczonym '\0'
int set_QNAME(dns_question_t * question, const char * domain);

#endif