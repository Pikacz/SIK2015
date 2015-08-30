#include "question.h"
#include "utils.h"
#include "globals.h"

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


int question_from_network(dns_question_t * question, char * buff, int max_size){
  char * tmp = buff;
  question->qname_length = get_NAME_from_net(question->QNAME, buff, max_size);
  if (question->qname_length < 0)
    return -1;
  max_size -= question->qname_length;
  buff += question->qname_length;

  if(max_size < 2)
    return -1;
  question->QTYPE = get_uint16_t(buff);
  buff += 2;
  max_size -= 2;

  if(max_size < 2)
    return -1;
  question->QCLASS = get_uint16_t(buff);
  buff += 2;
  max_size -= 2;
  return buff - tmp;
}


int is_qPTR(dns_question_t* q) {
  return (q->QCLASS == TYPE_PTR);
}

void set_qPTR(dns_question_t* q) {
  q->QCLASS = TYPE_PTR;
}
