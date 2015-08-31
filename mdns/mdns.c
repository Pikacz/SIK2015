#include <unistd.h> // gethostname
#include <string.h> //strcat

#include "mdns.h"


int answer_A(dns_question_t * question, dns_resource_t * answer) {
  static char hostname[90];
  gethostname(hostname, 63);
  strcat(hostname, "._opoznienia._udp.local.");

  if(is_qA(question)) {

  }
  return 0;
}
