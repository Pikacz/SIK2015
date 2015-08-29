#include <stdio.h>      //  NULL
#include <stdlib.h>     // srand, rand, RAND_MAX
#include <time.h>       // time
#include <string.h>     // strlen
#include <assert.h>
#include <inttypes.h>

#include "../../mdns/msg/header.h"
#include "../../mdns/msg/question.h"
#include "../../mdns/msg/utils.h"
#include "../../mdns/msg/resource.h"
#include "msg.h"


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


uint16_t my_rand16() {
  return my_rand(0, 0xFFFF);
}


char my_rand6() {
  return (char) (my_rand(0, 0x003F) & 0x003F);
}


char my_rand8() {
  return (char) (my_rand(0, 0x00FF) & 0x00FF);
}


uint32_t my_rand32() {
  uint32_t left = my_rand(0, 0xFFFF), right = my_rand(0, 0xFFFF);
  left  &= 0x0000FFFF;
  right &= 0x0000FFFF;
  left <<= 16;
  return left | right;
}


void check_uint16(uint16_t num) {
  char buff[2];
  assert(2 == unit16_to_send(num, buff));
  uint16_t result = get_uint16_t(buff);
  assert(num == result);
}


void check_uint32(uint32_t num) {
  char buff[4];
  assert(4 == unit32_to_send(num, buff));
  uint32_t result = get_uint32_t(buff);
  assert(num == result);
}


void utils() {
  int i, rounds = 1000000;// 000;
  fprintf(stderr, "DNS MSG UTILS TESTS:\n");
  fprintf(stderr, "   %d random uint16_t       ", rounds);
  for(i = 0; i < rounds; ++i)
    check_uint16(my_rand(0, 0xFFFF));
  fprintf(stderr, "SUCESS!\n");

  fprintf(stderr, "   %d random uint32_t       ", rounds);
  for(i = 0; i < rounds; ++i)
    check_uint32(my_rand32());
  fprintf(stderr, "SUCESS!\n");
}


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


void random_header(dns_header_t * header) {
  int i;
  for (i = 0; i < 6; ++i)
    (header->h)[i] = my_rand16();
}

void header_t2() {
  static char buff[12];
  int i;
  dns_header_t header1, header2;
  random_header(&header1);
  assert(12 == header_send_format(&header1, buff));
  header_from_network(&header2, buff);
  for (i = 0; i < 6; ++i)
    assert(header1.h[i] == header2.h[i]);
}


void header() {
  srand (time(NULL));
  int i;
  dns_header_t h;
  init_header(&h);
  valid_init(&h);
  int rounds = 1000000;// 000;
  fprintf(stderr, "DNS MSG HEADER TESTS:\n   %d random operations     ",
          rounds);
  fflush(stderr);
  header_t1(rounds);
  fprintf(stderr, "SUCESS!\n");

  fprintf(stderr, "   %d to/from network       ", rounds);
  for(i = 0; i < rounds; ++i)
    header_t2();
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


void q_t2() {
  int i;
  dns_question_t q;
  set_QNAME(&q, "www.a.pl");
  q.QTYPE = 0x1234;
  q.QCLASS = 0x5678;
  char ex[14], buff[231];
  ex[0]  = '\x03';
  ex[1]  = 'w';
  ex[2]  = 'w';
  ex[3]  = 'w';
  ex[4]  = '\x01';
  ex[5]  = 'a';
  ex[6]  = '\x02';
  ex[7]  = 'p';
  ex[8]  = 'l';
  ex[9]  = '\x00';
  ex[10] = '\x12';
  ex[11] = '\x34';
  ex[12] = '\x56';
  ex[13] = '\x78';

  assert(14 == question_send_format(&q, buff));
  for(i = 0; i < 14; ++i)
    assert(ex[i] == buff[i]);
  assert(q.qname_length == 10);
}


void q_t3() {
  dns_question_t q1, q2;
  char buff[400];
  set_QNAME(&q1, "www.a.pl");
  q1.QTYPE = 0x1234;
  q1.QCLASS = 0x5678;

  question_send_format(&q1, buff);
  question_from_network(&q2, buff);

  assert(q1.QCLASS == q2.QCLASS);
  assert(q1.QTYPE == q2.QTYPE);
  assert(q1.qname_length == q2.qname_length);
  int i;
  for (i = 0; i < q1.qname_length; ++i)
    assert((q1.QNAME)[i] == (q2.QNAME)[i]);

}


void random_question(dns_question_t * question) {
  question->QTYPE = my_rand16();
  question->QCLASS = my_rand16();
  question->qname_length = 0;
  int i;
  char* it = question->QNAME;
  char c, cc;
  for(i = 0; i < 2; ++i) {
    c = my_rand6();
    if (c == 0)
      c = 1;

    *it  = c;
    ++it;
    (question->qname_length)++;

    for(cc = 0; cc < c; ++cc) {
      *it  = my_rand8();
      ++it;
      (question->qname_length)++;
    }
  }
  *it = 0;
  (question->qname_length)++;
}


void q_t4() {
  dns_question_t q1, q2;
  char buff[400];
  random_question(&q1);

  question_send_format(&q1, buff);
  question_from_network(&q2, buff);

  assert(q1.QCLASS == q2.QCLASS);
  assert(q1.QTYPE == q2.QTYPE);
  assert(q1.qname_length == q2.qname_length);
  int i;
  for (i = 0; i < q1.qname_length; ++i)
    assert((q1.QNAME)[i] == (q2.QNAME)[i]);

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
  int rounds = 1000000;
  int i;
  fprintf(stderr, "   %d to/from network       ", rounds);
  q_t2();
  q_t3();
  for(i = 0; i < rounds; ++i)
    q_t4();
  fprintf(stderr, "SUCESS!\n");
}


void r_t1() {

}

void resource() {

}
