#ifndef MDNS_MSG_HEADER
#define MDNS_MSG_HEADER

#include <stdint.h>

struct __dns_header {
  uint16_t h[6];
};

typedef struct __dns_header dns_header_t;

#define DNS_HEADER_ID_MAX      0xFFFF
#define DNS_HEADER_QR_MAX      0x0001
#define DNS_HEADER_Opcode_MAX  0x000F
#define DNS_HEADER_AA_MAX      0x0001
#define DNS_HEADER_TC_MAX      0x0001
#define DNS_HEADER_RD_MAX      0x0001
#define DNS_HEADER_RA_MAX      0x0001
#define DNS_HEADER_Z_MAX       0x0007
#define DNS_HEADER_RCODE_MAX   0x000F
#define DNS_HEADER_QDCOUNT_MAX 0xFFFF
#define DNS_HEADER_ANCOUNT_MAX 0xFFFF
#define DNS_HEADER_NSCOUNT_MAX 0xFFFF
#define DNS_HEADER_ARCOUNT_MAX 0xFFFF

void init_header(dns_header_t * header);

void set_ID(dns_header_t * header, uint16_t id);
uint16_t get_ID(dns_header_t *header);

void set_QR(dns_header_t * header, uint16_t qr);
uint16_t get_QR(dns_header_t * header);

void set_Opcode(dns_header_t * header, uint16_t opcode);
uint16_t get_Opcode(dns_header_t * header);

void set_AA(dns_header_t * header, uint16_t aa);
uint16_t get_AA(dns_header_t * header);

void set_TC(dns_header_t * header, uint16_t tc);
uint16_t get_TC(dns_header_t * header);

void set_RD(dns_header_t * header, uint16_t rd);
uint16_t get_RD(dns_header_t * header);

void set_RA(dns_header_t * header, uint16_t ra);
uint16_t get_RA(dns_header_t * header);

void set_Z(dns_header_t * header, uint16_t z);
uint16_t get_Z(dns_header_t * header);

void set_RCODE(dns_header_t * header, uint16_t rcode);
uint16_t get_RCODE(dns_header_t * header);

void set_QDCOUNT(dns_header_t * header, uint16_t qdcount);
uint16_t get_QDCOUNT(dns_header_t *header);

void set_ANCOUNT(dns_header_t * header, uint16_t ancount);
uint16_t get_ANCOUNT(dns_header_t *header);

void set_NSCOUNT(dns_header_t * header, uint16_t nscount);
uint16_t get_NSCOUNT(dns_header_t *header);

void set_ARCOUNT(dns_header_t * header, uint16_t arcount);
uint16_t get_ARCOUNT(dns_header_t *header);

void print_header(dns_header_t * header);

int header_send_format(dns_header_t * header, char * buff);
void header_from_network(dns_header_t * header, char * buff);

#endif
