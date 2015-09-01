#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdns/msg/msg.h"
#include "mdns/msg/globals.h"
#include "mdns/msg/utils.h"


#define PORT 5353
#define IP "224.0.0.251"

int costam = 0;

int make_msg(char * buff) {
  static dns_msg_t msg;
  dns_question_t q;


  init_header(&(msg.header));

  set_QR(&(msg.header), QR_QUERY);

  set_QDCOUNT(&(msg.header), 1);
  set_ANCOUNT(&(msg.header), 0);
  set_NSCOUNT(&(msg.header), 0);
  set_ARCOUNT(&(msg.header), 0);
  if((costam % 2) == 0) {
    q.qname_length = domain_to_NAME(q.QNAME, "sikvm3._opoznienia._udp.local.");
    set_qA(&q);
  }
  else {
    q.qname_length = domain_to_NAME(q.QNAME, "_opoznienia._udp.local.");
    q.QTYPE = TYPE_PTR;
  }
  costam++;
  q.QCLASS = CLASS_IN;
  msg.questions = &q;


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
