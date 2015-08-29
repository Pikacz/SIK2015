#include <stdio.h>      /*  NULL */
#include <stdlib.h>     /* srand, rand, RAND_MAX*/
#include <time.h>       /* time */
#include <string.h>     // strlen
#include <assert.h>

#include "../../mdns/msg/header.h"
#include "../../mdns/msg/question.h"
#include "msg.h"


void check_header(dns_header_t * header, uint16_t id, uint16_t qr,
                  uint16_t opcode, uint16_t aa, uint16_t tc, uint16_t rd,
                  uint16_t ra, uint16_t z, uint16_t rcode, uint16_t qdcount,
                  uint16_t ancount, uint16_t nscount, uint16_t arcount) {
  int i;
  for (i = 0; i < 3; ++i) {
    assert(get_ID(header) == id);
    assert(get_QR(header) == qr);
    assert(get_Opcode(header) == opcode);
    assert(get_AA(header) == aa);
    assert(get_TC(header) == tc);
    assert(get_RD(header) == rd);
    assert(get_RA(header) == ra);
    assert(get_Z(header) == z);
    assert(get_RCODE(header) == rcode);
    assert(get_QDCOUNT(header) == qdcount);
    assert(get_ANCOUNT(header) == ancount);
    assert(get_NSCOUNT(header) == nscount);
    assert(get_ARCOUNT(header) == arcount);
  }
}


void valid_init(dns_header_t * header) {
  check_header(header, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}


uint16_t my_rand(uint16_t min, uint32_t range) {
  range += 1;
  assert(range >= 1);
  if (range == 1)
    return min;

  if (range <= RAND_MAX) {
    return min + (rand() % range);
  }

  do {
    range -= RAND_MAX;
    min += rand();
  } while (range > RAND_MAX);
  assert(range > 0);
  return min + (rand() % range);
}


void header_t1(int rounds) {
  static uint16_t id = 0, qr = 0, opcode = 0, aa = 0, tc = 0, rd = 0, ra = 0,
                  z = 0, rcode = 0, qdcount = 0, ancount = 0, nscount = 0,
                  arcount = 0, change_id;
  dns_header_t h;
  init_header(&h);
  int i;
  for (i = 0; i < rounds; ++i) {
    check_header(&h, id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount,
                 nscount, arcount);
    change_id = my_rand(0, 14);
    switch (change_id) {
      case 0:
        id = my_rand(0, DNS_HEADER_ID_MAX);
        set_ID(&h, id);
        break;

      case 1:
        qr = my_rand(0, DNS_HEADER_QR_MAX);
        set_QR(&h, qr);
        break;

      case 2:
        opcode = my_rand(0, DNS_HEADER_Opcode_MAX);
        set_Opcode(&h, opcode);
        break;

      case 3:
        aa = my_rand(0, DNS_HEADER_AA_MAX);
        set_AA(&h, aa);
        break;

      case 4:
        tc = my_rand(0, DNS_HEADER_TC_MAX);
        set_TC(&h, tc);
        break;

      case 5:
        rd = my_rand(0, DNS_HEADER_RD_MAX);
        set_RD(&h, rd);
        break;

      case 6:
        ra = my_rand(0, DNS_HEADER_RA_MAX);
        set_RA(&h, ra);
        break;

      case 7:
        z = my_rand(0, DNS_HEADER_Z_MAX);
        set_Z(&h, z);
        break;

      case 8:
        rcode = my_rand(0, DNS_HEADER_RCODE_MAX);
        set_RCODE(&h, rcode);
        break;

      case 9:
        qdcount = my_rand(0, DNS_HEADER_QDCOUNT_MAX);
        set_QDCOUNT(&h, qdcount);
        break;

      case 10:
        ancount = my_rand(0, DNS_HEADER_ANCOUNT_MAX);
        set_ANCOUNT(&h, ancount);
        break;

      case 11:
        nscount = my_rand(0, DNS_HEADER_NSCOUNT_MAX);
        set_NSCOUNT(&h, nscount);
        break;

      case 12:
        arcount = my_rand(0, DNS_HEADER_ARCOUNT_MAX);
        set_ARCOUNT(&h, arcount);
        break;

      case 13:
        id = qr = opcode = aa = tc = rd = ra = z = rcode = qdcount = ancount =
          nscount = arcount = 0;
        init_header(&h);
        break;
    }
  }
}


void header() {
  srand (time(NULL));
  dns_header_t h;
  init_header(&h);
  valid_init(&h);
  int rounds = 1000000;// 000;
  fprintf(stderr, "DNS MSG HEADER TESTS:\n   %d random operations     ", rounds);
  fflush(stderr);
  header_t1(rounds);
  fprintf(stderr, "SUCESS!\n");
}


void check_set_qname(const char* domain, const char * expected) {
  dns_question_t q;
  int i;
  int length = strlen(expected) + 1;
  assert(length == set_QNAME(&q, domain));
  for (i = 0; i < length; ++i) {
    assert(q.QNAME[i] == expected[i]);
  }
}


void question() {
  fprintf(stderr, "DNS MSG QUESTION TESTS:\n");
  fprintf(stderr, "   check_set_qname ");
  fflush(stderr);
  check_set_qname("www.a.pl",  "\x03" "www" "\x01" "a" "\x02" "pl");
  // fun fact "\x01a" == "\x1a" == { 26 }
  check_set_qname("www.a.pl.", "\x03" "www" "\x01" "a" "\x02" "pl");
  check_set_qname("MyComputer.local.","\x0a""MyComputer" "\x05" "local");
  check_set_qname("MyComputer.local", "\x0a""MyComputer" "\x05" "local");
  fprintf(stderr, "              SUCESS!\n");
}
