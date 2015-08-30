#include <stdio.h>      //  NULL
#include <stdlib.h>     // srand, rand, RAND_MAX
#include <time.h>       // time
#include <string.h>     // strlen
#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>


#include "../../mdns/msg/header.h"
#include "../../mdns/msg/question.h"
#include "../../mdns/msg/utils.h"
#include "../../mdns/msg/resource.h"
#include "../../mdns/msg/msg.h"
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
  check_uint16(0);
  for(i = 0; i < rounds; ++i)
    check_uint16(my_rand(0, 0xFFFF));
  fprintf(stderr, "SUCESS!\n");

  fprintf(stderr, "   %d random uint32_t       ", rounds);
  check_uint32(0);
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
  header_from_network(&header2, buff, 12);
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
  assert(question_from_network(&q2, buff, 1) == -1);
  question_from_network(&q2, buff, 400);

  assert(q1.QCLASS == q2.QCLASS);
  assert(q1.QTYPE == q2.QTYPE);
  assert(q1.qname_length == q2.qname_length);
  int i;
  for (i = 0; i < q1.qname_length; ++i)
    assert((q1.QNAME)[i] == (q2.QNAME)[i]);

}


int random_name(char * it) {
  int length = 0, i;
  char c, cc;
  for(i = 0; i < 2; ++i) {
    c = my_rand6();
    if (c <= 0)
      c = 1;
    if (c > 63)
      c = 63;

    *it  = c;
    ++it;
    length++;

    for(cc = 0; cc < c; ++cc) {
      *it  = my_rand8();
      ++it;
      length++;
    }
  }
  *it = 0;
  length++;
  return length;
}

void random_question(dns_question_t * question) {
  question->QTYPE = my_rand16();
  question->QCLASS = my_rand16();
  question->qname_length = random_name(question->QNAME);
}


void q_t4() {
  dns_question_t q1, q2;
  char buff[400];
  random_question(&q1);

  question_send_format(&q1, buff);
  assert(question_from_network(&q2, buff, 1) == -1);
  question_from_network(&q2, buff, 400);

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
  dns_resource_t res;
  int i;
  const char * name = "\x03" "www" "\x01" "a" "\x02" "pl";
  static char ex[23], buff[200];
  for(i = 0; i < 10; ++i)
    res.NAME[i] = name[i];
  res.TYPE = 0x1234;
  res.CLASS = 0x5678;
  res.TTL = 0x87654321;
  res.RDLENGTH = 0x03;
  res.RDATA[0] = 'b';
  res.RDATA[1] = 'c';
  res.RDATA[2] = 'd';

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
  ex[14] = (char)((0x87654321 & 0xFF000000) >> 24);
  ex[15] = (char)((0x87654321 & 0x00FF0000) >> 16);
  ex[16] = (char)((0x87654321 & 0x0000FF00) >> 8);
  ex[17] = (char)((0x87654321 & 0x000000FF) >> 0);
  ex[18] = (char)((0x03 & 0xFF00) >> 8);
  ex[19] = (char)((0x03 & 0x00FF) >> 0);
  ex[20] = 'b';
  ex[21] = 'c';
  ex[22] = 'd';
  int tmp = resource_send_format(&res, buff);
  assert(tmp == 23);
  for(i = 0; i < 23; ++i) {
    assert(ex[i] == buff[i]);
  }

}

void rand_resource(dns_resource_t * res) {
  random_name(res->NAME);
  res->TYPE = my_rand16();
  res->CLASS = my_rand16();
  res->TTL = my_rand32();

  res->RDLENGTH = my_rand(0,20);

  int i;
  for(i = 0; i < res->RDLENGTH; ++i) {
    (res->RDATA)[i] = my_rand8();
  }
}

void names_equal(char * n1, char * n2) {
  int i = 0;

  while((n1[i] != 0) &&(n2[i] != 0)) {
    assert(n1[i] == n2[i]);
    i++;
  }
  assert(n1[i] == n2[i]);
}



void r_t2() {
  dns_resource_t r1, r2;
  rand_resource(&r1);
  char buff[400];
  resource_send_format(&r1, buff);
  assert(resource_from_network(&r2, buff, 1) == -1);
  resource_from_network(&r2, buff, 400);
  names_equal(r1.NAME, r2.NAME);
  assert(r1.TYPE == r2.TYPE);
  assert(r1.CLASS == r2.CLASS);
  assert(r1.TTL == r2.TTL);
  assert(r1.RDLENGTH == r2.RDLENGTH);
  int i;
  for(i = 0; i < r1.RDLENGTH; ++i)
    assert(r1.RDATA[i] == r2.RDATA[i]);

}

void resource() {
  r_t1();
  int i, rounds = 1000000;
  fprintf(stderr, "DNS MSG RESOURCE TESTS:\n   %d random resources      ",
          rounds);
  for(i = 0; i < rounds; ++i)
    r_t2();
  fprintf(stderr, "SUCESS!\n");
}


void headers_equal(dns_header_t * h1, dns_header_t * h2) {
  int i;
  for (i = 0; i < 6; ++i) {
    assert((h1->h)[i] == (h2->h)[i]);
  }
}


void questions_equal(dns_question_t * q1, dns_question_t * q2) {
  assert(q1->QCLASS == q2->QCLASS);
  assert(q1->QTYPE == q2->QTYPE);
}

void resources_equal(dns_resource_t * r1, dns_resource_t * r2) {
  assert(r1->TYPE == r2->TYPE);
  assert(r1->CLASS == r2->CLASS);
  assert(r1->TTL == r2->TTL);
  assert(r1->RDLENGTH == r2->RDLENGTH);
  names_equal(r1->NAME, r2->NAME);
}


void messages_equal(dns_msg_t * m1, dns_msg_t * m2) {
  int i;
  headers_equal(&(m1->header), &(m2->header));
  for(i = 0; i < get_QDCOUNT(&(m1->header)); ++i) {
    questions_equal((m1->questions) + i, (m2->questions) + i);
  }

  for(i = 0; i < get_ANCOUNT(&(m1->header)); ++i) {
    resources_equal((m1->answers) + i, (m2->answers) + i);
  }

  for(i = 0; i < get_NSCOUNT(&(m1->header)); ++i) {
    resources_equal((m1->authorities) + i, (m2->authorities) + i);
  }

  for(i = 0; i < get_ARCOUNT(&(m1->header)); ++i) {
    resources_equal((m1->additionals) + i, (m2->additionals) + i);
  }

}


void m_1() {
  dns_msg_t msg;
  dns_question_t q;
  dns_resource_t ans, auth, add;

  static char ex[123], buff[1000000];
  init_header(&(msg.header));
  set_ID(&(msg.header), 13);
  set_QR(&(msg.header), 1);
  set_Opcode(&(msg.header), 10);
  set_AA(&(msg.header), 0);
  set_TC(&(msg.header), 1);
  set_Z(&(msg.header), 1);
  set_QDCOUNT(&(msg.header), 1);
  set_ANCOUNT(&(msg.header), 1);
  set_NSCOUNT(&(msg.header), 1);
  set_ARCOUNT(&(msg.header), 1);
  q.QNAME[0] = 1;
  q.QNAME[1] = 11;
  q.QNAME[2] = 2;
  q.QNAME[3] = 31;
  q.QNAME[4] = 32;
  q.QNAME[5] = 0;
  q.qname_length = 6;
  q.QTYPE = 0x5667;
  q.QCLASS = 0x7665;
  msg.questions = &q;

  ans.NAME[0] = 2;
  ans.NAME[1] = 21;
  ans.NAME[2] = 22;
  ans.NAME[3] = 1;
  ans.NAME[4] = 11;
  ans.NAME[5] = 0;
  ans.TYPE = 0x1212;
  ans.CLASS = 0x2121;
  ans.TTL = 0x87654321;
  ans.RDLENGTH = 1;
  ans.RDATA[0] = 43;
  msg.answers = &ans;

  auth.NAME[0] = 2;
  auth.NAME[1] = 23;
  auth.NAME[2] = 24;
  auth.NAME[3] = 1;
  auth.NAME[4] = 12;
  auth.NAME[5] = 0;
  auth.TYPE = 0x1221;
  auth.CLASS = 0x2112;
  auth.TTL = 0x87654321;
  auth.RDLENGTH = 1;
  auth.RDATA[0] = 44;
  msg.authorities = &auth;

  add.NAME[0] = 2;
  add.NAME[1] = 25;
  add.NAME[2] = 26;
  add.NAME[3] = 1;
  add.NAME[4] = 13;
  add.NAME[5] = 0;
  add.TYPE = 0x1221;
  add.CLASS = 0x2112;
  add.TTL = 0x87654321;
  add.RDLENGTH = 0;
  msg.additionals = &add;

  int tmp;
  tmp = send_format_msg(&msg, buff);

  // header
  ex[0] = (char)((13 & 0xFF00) >> 8);
  ex[1] = (char)((13 & 0x00FF));
  ex[2] = 0xd2;
  ex[3] = 0x10;
  ex[4] = (char)((0x0001 & 0xFF00) >> 8);
  ex[5] = (char)((0x0001 & 0x00FF));
  ex[6] = (char)((0x0001 & 0xFF00) >> 8);
  ex[7] = (char)((0x0001 & 0x00FF));
  ex[8] = (char)((0x0001 & 0xFF00) >> 8);
  ex[9] = (char)((0x0001 & 0x00FF));
  ex[10] = (char)((0x0001 & 0xFF00) >> 8);
  ex[11] = (char)((0x0001 & 0x00FF));

  // questions
  ex[12] = 1;
  ex[13] = 11;
  ex[14] = 2;
  ex[15] = 31;
  ex[16] = 32;
  ex[17] = 0;
  ex[18] = 0x56;
  ex[19] = 0x67;
  ex[20] = 0x76;
  ex[21] = 0x65;

  // answers
  ex[22] = 2;
  ex[23] = 21;
  ex[24] = 22;
  ex[25] = 1;
  ex[26] = 11;
  ex[27] = 0;
  ex[28] = 0x12;
  ex[29] = 0x12;
  ex[30] = 0x21;
  ex[31] = 0x21;

  ex[32] = (char)((0x87654321 & 0xFF000000) >> 24);
  ex[33] = (char)((0x87654321 & 0x00FF0000) >> 16);
  ex[34] = (char)((0x87654321 & 0x0000FF00) >> 8);
  ex[35] = (char)((0x87654321 & 0x000000FF) >> 0);

  ex[36] = (char)((0x0001 & 0xFF00) >> 8);
  ex[37] = (char)((0x0001 & 0x00FF));
  ex[38] = 43;

  // authorities
  ex[39] = 2;
  ex[40] = 23;
  ex[41] = 24;
  ex[42] = 1;
  ex[43] = 12;
  ex[44] = 0;
  ex[45] = 0x12;
  ex[46] = 0x21;
  ex[47] = 0x21;
  ex[48] = 0x12;

  ex[49] = (char)((0x87654321 & 0xFF000000) >> 24);
  ex[50] = (char)((0x87654321 & 0x00FF0000) >> 16);
  ex[51] = (char)((0x87654321 & 0x0000FF00) >> 8);
  ex[52] = (char)((0x87654321 & 0x000000FF) >> 0);

  ex[53] = (char)((0x0001 & 0xFF00) >> 8);
  ex[54] = (char)((0x0001 & 0x00FF));
  ex[55] = 44;

  // additionals
  ex[56] = 2;
  ex[57] = 25;
  ex[58] = 26;
  ex[59] = 1;
  ex[60] = 13;
  ex[61] = 0;
  ex[62] = 0x12;
  ex[63] = 0x21;

  ex[64] = 0x21;
  ex[65] = 0x12;

  ex[66] = (char)((0x87654321 & 0xFF000000) >> 24);
  ex[67] = (char)((0x87654321 & 0x00FF0000) >> 16);
  ex[68] = (char)((0x87654321 & 0x0000FF00) >> 8);
  ex[69] = (char)((0x87654321 & 0x000000FF) >> 0);

  ex[70] = (char)((0x0000 & 0xFF00) >> 8);
  ex[71] = (char)((0x0000 & 0x00FF));

  assert(tmp == 72);

  int i;
  for(i = 0; i < 72; ++i)
    assert(ex[i] == buff[i]);
  dns_msg_t m;
  assert(message_from_network(&m, buff, 1) == -1);
  message_from_network(&m, buff, 1000000);
  assert((msg.header.h)[0] == (m.header.h)[0]);
  assert((msg.header.h)[1] == (m.header.h)[1]);
  assert((msg.header.h)[2] == (m.header.h)[2]);
  assert((msg.header.h)[3] == (m.header.h)[3]);
  assert((msg.header.h)[4] == (m.header.h)[4]);
  assert((msg.header.h)[5] == (m.header.h)[5]);

  messages_equal(&msg, &m);
}

void message() {
  fprintf(stderr, "DNS MSG MSG TESTS:\n");
  m_1();
  fprintf(stderr, "SUCESS!\n");
}
