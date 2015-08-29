#include "question.h"
#include "utils.h"

#include <stdio.h>


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
  question->qname_length = s - question->QNAME + 1;
  return question->qname_length;
}


int question_send_format(dns_question_t * question, char * buff) {
  int i, size = 0, tmp;
  for(i = 0; i < question->qname_length; ++i) {
    *buff = question->QNAME[i];
    ++buff;
  }
  size += question->qname_length;
  tmp = unit16_to_send(question->QTYPE, buff);
  size += tmp;
  buff += tmp;
  tmp = unit16_to_send(question->QCLASS, buff);
  size += tmp;
  return size;
}


void question_from_network(dns_question_t * question, char * buff) {
  char c = buff[0], i = 0;
  int j = 0;

  question->qname_length = 1;
  (question->QNAME)[j] = *buff;
  buff++;
  j++;

  while(c) {
    for(i = 0; i < c; ++i) {
      (question->QNAME)[j] = *buff;
      buff++;
      j++;
      question->qname_length += 1;
    }
    c = *buff;
    (question->QNAME)[j] = *buff;
    buff++;
    j++;
    question->qname_length += 1;
  }

  question->QTYPE = get_uint16_t(buff);
  buff += 2;
  question->QCLASS = get_uint16_t(buff);
}
