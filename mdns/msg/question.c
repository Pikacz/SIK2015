#include "question.h"

#include <stdio.h>

// struct __dns_question {
//   uint16_t QTYPE;
//   uint16_t QCLASS;
//   char * QNAME;
// };

void set_QU(dns_question_t * question) {
  question->QTYPE |= 0x8000;
}

void set_QM(dns_question_t * question) {
  question->QTYPE &= (~0x8000);
}

uint16_t is_QM(dns_question_t * question) {
  return (question->QTYPE & 0x8000);
}

int set_QNAME(dns_question_t * question, const char * domain) {
  int i = 0;
  char l_size = 0;
  char * s = question->QNAME;

  while(1) {
    while(domain[i + l_size] != '.' && domain[i + l_size] != '\0') {
      l_size++;
      if (l_size > DNS_Q_QLABEL_MAX_LENGTH)
        return -1;
    }

    *s = l_size;
    s++;

    while (l_size) {
      if (i >= DNS_Q_QNAME_MAX_LENGTH)
        return -1;
      *s = domain[i];
      i++;
      s++;
      l_size--;
    }
    if (domain[i] == '.')
      i++;
    if (domain[i] == '\0') {
      *s = domain[i];
      break;
    }
  }

  return s - question->QNAME + 1;
}
