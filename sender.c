#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdns/msg/msg.h"

#define PORT 5353
#define IP "224.0.0.251"

int make_msg(char * buff) {
  dns_msg_t msg;
  dns_question_t q;
  dns_resource_t ans, auth, add;

  init_header(&(msg.header));
  set_ID(&(msg.header), 13);
  set_QR(&(msg.header), 1);
  set_Opcode(&(msg.header), 10);
  set_AA(&(msg.header), 1);
  set_TC(&(msg.header), 0);
  set_Z(&(msg.header), 2);
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
  set_qA(&q);
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
  ans.TTL = 100;
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
  auth.TTL = 100;
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
  add.TTL = 100;
  add.RDLENGTH = 0;
  msg.additionals = &add;
  return send_format_msg(&msg, buff);
}

#define MAX_LEN  1024

int main(int argc, char *argv[])
{
	int sock;
	char message_to_send[MAX_LEN];
	unsigned int send_len;
	const char* multicast_ip;
	unsigned short multicast_port;
	unsigned char multicast_ttl=1;
	struct sockaddr_in multicast_addr;



	multicast_ip = IP;       /* arg 1: multicast IP address */
	multicast_port     = PORT; /* arg 2: multicast port number */

	/* create a socket */
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("Socket creation failed");
		exit(1);
	}

	/* set the TTL (time to live/hop count) for the send */
	if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*) &multicast_ttl, sizeof(multicast_ttl))) < 0)
	{
		perror("setsockopt() failed");
		exit(1);
	}

	memset(&multicast_addr, 0, sizeof(multicast_addr));
	multicast_addr.sin_family      = AF_INET;
	multicast_addr.sin_addr.s_addr = inet_addr(multicast_ip);
	multicast_addr.sin_port        = htons(multicast_port);

	printf("Type the message below (Press Enter to send, ctrl-C to quit):\n");

	memset(message_to_send, 0, sizeof(message_to_send));

	while (fgets(message_to_send, MAX_LEN, stdin))
	{

		send_len = make_msg(message_to_send);

		if ((sendto(sock, message_to_send, send_len, 0,
		(struct sockaddr *) &multicast_addr,
		sizeof(multicast_addr))) != send_len)
		{
			perror("Error in number of bytes");
			exit(1);
		}

		memset(message_to_send, 0, sizeof(message_to_send));
	}

	close(sock);

	exit(0);
}
