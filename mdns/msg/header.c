// header
//                                        1  1  1  1  1  1
//          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h0     |                      ID                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h1     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h2     |                    QDCOUNT                    |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h3     |                    ANCOUNT                    |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h4     |                    NSCOUNT                    |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// h5     |                    ARCOUNT                    |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


#include "header.h"
#include "utils.h"

#include <netinet/in.h> // htons
#include <assert.h>     // assert
#include <string.h>     // memset

#include <stdio.h>


void init_header(dns_header_t * header) {
  memset((header->h), 0, sizeof((header->h)));
}


void set_ID(dns_header_t * header, uint16_t id) {
  (header->h)[0] = id;
}


uint16_t get_ID(dns_header_t *header) {
  return (header->h)[0];
}


void set_QR(dns_header_t * header, uint16_t qr) {
  assert((qr == 1) || (qr == 0));
  if (qr)
    (header->h)[1] |= 0x8000;
  else
    (header->h)[1] &= (~0x8000);
}


uint16_t get_QR(dns_header_t * header) {
  if (((header->h)[1]) & 0x8000)
    return 1;
  return 0;
}


void set_Opcode(dns_header_t * header, uint16_t opcode) {
  assert((opcode >= 0) && (opcode <= DNS_HEADER_Opcode_MAX));
  ((header->h)[1]) &= (~0x7800);
  // (header->h)[1]) = x000 0xxx xxxx xxxx
  opcode = opcode << 11;
  // opcode = 0yyy y000 0000 0000
  ((header->h)[1]) |= opcode;
  // (header->h)[1]) = xyyy yxxx xxxx xxxx
}


uint16_t get_Opcode(dns_header_t * header) {
  uint16_t tmp = 0x7800;
  tmp = ((header->h)[1]) & tmp;
  tmp >>= 11;
  return tmp;
}


void set_AA(dns_header_t * header, uint16_t aa) {
  assert((aa == 1) || (aa == 0));
  if (aa)
    (header->h)[1] |= 0x0400;
  else
    (header->h)[1] &= (~0x0400);
}


uint16_t get_AA(dns_header_t * header) {
  if (((header->h)[1]) & 0x0400)
    return 1;
  return 0;
}


void set_TC(dns_header_t * header, uint16_t tc) {
  assert((tc == 1) || (tc == 0));
  if (tc)
    (header->h)[1] |= 0x0200;
  else
    (header->h)[1] &= (~0x0200);
}


uint16_t get_TC(dns_header_t * header) {
  if (((header->h)[1]) & 0x0200)
    return 1;
  return 0;
}


void set_RD(dns_header_t * header, uint16_t rd) {
  assert((rd == 1) || (rd == 0));
  if (rd)
    (header->h)[1] |= 0x0100;
  else
    (header->h)[1] &= (~0x0100);
}


uint16_t get_RD(dns_header_t * header) {
  if (((header->h)[1]) & 0x0100)
    return 1;
  return 0;
}


void set_RA(dns_header_t * header, uint16_t ra) {
  assert((ra == 1) || (ra == 0));
  if (ra)
    (header->h)[1] |= 0x0080;
  else
    (header->h)[1] &= (~0x0080);
}


uint16_t get_RA(dns_header_t * header) {
  if (((header->h)[1]) & 0x0080)
    return 1;
  return 0;
}


void set_Z(dns_header_t * header, uint16_t z) {
  assert((z >= 0) && (z <= DNS_HEADER_Z_MAX));
  ((header->h)[1]) &= (~0x0070);
  // (header->h)[1]) = xxxx xxxx x000 xxxx
  z <<= 4;
  // z = 0000 0000 0yyy 0000
  ((header->h)[1]) |= z;
  // (header->h)[1]) = xxxx xxxx xyyy xxxx
}


uint16_t get_Z(dns_header_t * header) {
  uint16_t tmp = 0x0070;
  tmp = ((header->h)[1]) & tmp;
  tmp >>= 4;
  return tmp;
}


void set_RCODE(dns_header_t * header, uint16_t rcode) {
  assert((rcode >= 0) && (rcode <= DNS_HEADER_RCODE_MAX));
  ((header->h)[1]) &= (~0x000F);
  ((header->h)[1]) |= rcode;
}


uint16_t get_RCODE(dns_header_t * header) {
  return ((header->h)[1]) & 0x000F;
}


void set_QDCOUNT(dns_header_t * header, uint16_t qdcount) {
  (header->h)[2] = qdcount;
}


uint16_t get_QDCOUNT(dns_header_t *header) {
  return (header->h)[2];
}


void set_ANCOUNT(dns_header_t * header, uint16_t ancount) {
  (header->h)[3] = ancount;
}


uint16_t get_ANCOUNT(dns_header_t *header) {
  return (header->h)[3];
}


void set_NSCOUNT(dns_header_t * header, uint16_t nscount) {
  (header->h)[4] = nscount;
}


uint16_t get_NSCOUNT(dns_header_t *header) {
  return (header->h)[4];
}


void set_ARCOUNT(dns_header_t * header, uint16_t arcount) {
  (header->h)[5] = arcount;
}


uint16_t get_ARCOUNT(dns_header_t *header) {
  return (header->h)[5];
}


void print_header(dns_header_t * header) {
  int i;
  for(i = 0; i < 6; ++i)
    printf("%04x\n", header->h[i]);
}


int header_send_format(dns_header_t * header, char * buff) {
  int size = 0, tmp;

  tmp = unit16_to_send((header->h)[0], buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send((header->h)[1], buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send((header->h)[2], buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send((header->h)[3], buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send((header->h)[4], buff);
  size += tmp;
  buff += tmp;

  tmp = unit16_to_send((header->h)[5], buff);
  size += tmp;
  buff += tmp;

  return size;
}

int header_from_network(dns_header_t * header, char * buff) {
  int i;
  for(i = 0; i < 6; ++i) {
    (header->h)[i] = get_uint16_t(buff);
    buff += 2;
  }
  (header->h)[0] = (header->h)[0];
  return 12;
}
