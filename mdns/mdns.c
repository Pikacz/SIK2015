#include <unistd.h> // gethostname
#include <string.h> //strcat
#include <arpa/inet.h>
#include <stdio.h>

#include "mdns.h"
#include "msg/globals.h"
#include "msg/utils.h"


static char hostname[100], tmp[100], service[100], tmp2[100];
static int hcounter = 0, hlen, slen;

void init_mdns() {

  gethostname(tmp,55);

  strcpy(tmp2, tmp);
  if(hcounter)
    sprintf(tmp, "%s_%d", tmp2, hcounter);

  hcounter++;
  strcat(tmp, "._opoznienia._udp.local.");
  domain_to_NAME(hostname, tmp);
  hlen = strlen(hostname);
  strcpy(service, "_opoznienia._udp.local.");
  slen = strlen(service);
}


int answer_A(dns_question_t * question, dns_resource_t * answer,
   uint32_t myip) {

  int eq = 1, i;
  if(question->QCLASS != CLASS_IN)
    return -1;
  if(is_qA(question)) {
    for(i = 0; (i < hlen + 1) && eq; ++i) {
      if(hostname[i] != (question->QNAME)[i])
        eq = 0;
    }
    if(!eq)
      return -1;

    answer->NAME[0] = '\0';
    strcpy(answer->NAME, hostname);

    answer->CLASS = CLASS_IN;
    answer->TYPE = TYPE_A;
    answer->RDLENGTH = 4;
    *(uint32_t*)(answer->RDATA) = htonl(myip);
  }
  else if (is_qPTR(question)) {
    for(i = 0; (i < slen + 1) && eq; ++i) {
      if(service[i] != (question->QNAME)[i])
        eq = 0;
    }
    if(!eq)
      return -1;

    answer->CLASS = CLASS_IN;
    answer->TYPE = TYPE_PTR;
    answer->RDLENGTH = hlen + 1;
    strcpy(answer->RDATA, hostname);
  }
  else
    return -1;
  return 0;
}

void ask_A(char * host_to_res, dns_question_t * question) {
  set_qA(question);
  question->QCLASS = CLASS_IN;
  strcpy(question->QNAME, host_to_res);
  question->qname_length = strlen(host_to_res) + 1;
}

void ask_PTR(char * serv, dns_question_t * question) {
  question->QTYPE = TYPE_PTR;
  question->QCLASS = CLASS_IN;
  strcpy(question->QNAME, serv);
  question->qname_length = strlen(serv) + 1;
}
