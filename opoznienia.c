#include <event2/event.h>
#include <event2/util.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>
#include <signal.h>


#include "mdns/msg/msg.h"
#include "mdns/mdns.h"
#include "mdns/msg/globals.h"

#define MULTICAST_PORT 5353
#define MULTICAST_IP "224.0.0.251"

#define MDNS_MAX_LEN 100000

#define INTERFACES_MAX 10
static uint32_t my_ip;

// odstep sekundowy odswierzania opoznien, odkrywania komputerow, ui
double delay_ref = 1, discovery_ref = 10, ui_ref = 1;
// port udp opoznien, tcp telnetu
int delay_port = 3382, ui_port = 3637;
// czy rozglaszamy tcp
int ssh_tcp = 0;

struct sockaddr_in multicast_addr;

struct con_desc {
  struct sockaddr_in address;
  evutil_socket_t sock;
  struct event *ev;
};

typedef struct con_desc con_desc_t;



uint64_t current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL);
    uint64_t useconds = te.tv_sec*1000000LL + te.tv_usec;
    return useconds;
}

void init_ip() {
  const char* google_dns_server = "8.8.8.8";
  int dns_port = 53;
  struct sockaddr_in serv;
  int sock = socket ( AF_INET, SOCK_DGRAM, 0);

  if(sock < 0) {
    fprintf(stderr, "nie udalo sie utworzyc socketa ip\n");
    exit(-1);
  }

  memset( &serv, 0, sizeof(serv) );
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr( google_dns_server );
  serv.sin_port = htons( dns_port );

  connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  getsockname(sock, (struct sockaddr*) &name, &namelen);

  char buffer[100];
  const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
  my_ip = htonl(name.sin_addr.s_addr);
  if(p == NULL) {
    fprintf(stderr, "nie udalo sie zdobyc ip z polaczenia\n");
    printf("Local ip is : %s \n" , buffer);
  }

  close(sock);
}

evutil_socket_t get_multi_sock() {
    evutil_socket_t sock;
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock == -1 ||
        evutil_make_listen_socket_reuseable(sock) ||
        evutil_make_socket_nonblocking(sock)) {
        fprintf(stderr, "blad podczas tworzenia socketa multicast\n");
        exit(-1);
    }


    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_IP);//htonl(INADDR_ANY);
    multicast_addr.sin_port = htons(MULTICAST_PORT);
    if ((bind(sock, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) < 0) {
        fprintf(stderr, "blad podczas wiazania socketa multicast\n");
        exit(-1);
    }

    struct ip_mreq ipmreq;
    ipmreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_IP);
    ipmreq.imr_interface.s_addr = INADDR_ANY;

    if ((setsockopt(sock , IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &ipmreq,
                    sizeof(ipmreq))) < 0) {
          fprintf(stderr, "blad podczas ustawiania grupy socketa multicast\n");
          exit(-1);
    }

    int loop = 0;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
                   sizeof(loop)) < 0) {
      fprintf(stderr, "blad podczas wylaczania petli socketa multicast\n");
      exit(-1);
    }
    return sock;
}


evutil_socket_t get_delay_sock() {
  evutil_socket_t sock;
	struct sockaddr_in server_address;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0){
    fprintf(stderr, "blad podcas tworzenia socketa opoznien\n");
    exit(-1);
  }

	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(delay_port);

	if (bind(sock, (struct sockaddr *) &server_address,
	   (socklen_t) sizeof(server_address)) ||
     evutil_make_listen_socket_reuseable(sock) ||
     evutil_make_socket_nonblocking(sock)) {
    fprintf(stderr, "blad podcas wiazania socketa opoznien\n");
    exit(-1);
  }

  return sock;
}

// Events

void sigint_cb(evutil_socket_t sock, short ev, void *arg) {

	printf("Papa :* <3\n");
	event_base_loopexit((struct event_base *) arg, NULL);
}

void udp_delays_ans_cb(evutil_socket_t sock, short ev, void *arg) {
  static uint64_t udp_delays_buff[2];
  struct sockaddr_in client_address;
  socklen_t rcva_len;
  ssize_t len;

  len = recvfrom(sock, (char *)udp_delays_buff, 8, 0,
      (struct sockaddr *) &client_address, &rcva_len);
  if (len != 8)
    return; // miala byc liczba 64 bitowa, nie musze zachowywac jakiejs
            // smiesznej zgodnosci
  udp_delays_buff[1] = htobe64(current_timestamp());
  sendto(sock, udp_delays_buff, (size_t) 16, 0,
      (struct sockaddr *) &client_address, rcva_len);
  // nie dalo sie wyslac, coz zyje sie dalej :p
}

void multicast_rcv_cb(evutil_socket_t sock, short ev, void *arg) {
    static char rcv_buff[MDNS_MAX_LEN], ans_buff[MDNS_MAX_LEN];
    static struct sockaddr_in from_addr;
    static int rcv_len, snd_len;
    static unsigned int from_len;
    static dns_msg_t rcv, ans;
    static dns_resource_t ans_r;
    static int i;

    init_msg(&rcv);



    memset(rcv_buff, 0, sizeof(rcv_buff));
    memset(&from_addr, 0, sizeof(from_addr));


    if ((rcv_len = recvfrom(sock, rcv_buff, MDNS_MAX_LEN, 0,
      (struct sockaddr*)&from_addr, &from_len)) < 0) {
        return;
    }

    printf("Received %d bytes from %s: ", rcv_len,
           inet_ntoa(from_addr.sin_addr));

    if(message_from_network(&rcv, rcv_buff, MDNS_MAX_LEN) < 0) {
      printf("bledna wiadomosc\n");
    }
    else {
      if(get_QR(&(rcv.header)) == QR_QUERY) {
        printf("pytanie %d\n", get_QDCOUNT(&(rcv.header)));
        for(i = 0; i < get_QDCOUNT(&(rcv.header)); ++i) {
          if(answer(rcv.questions + i, &ans_r, my_ip) == 0) {
            //potrafie odpowiedziec
            init_msg(&ans);
            set_QR(&(ans.header), QR_RESPONSE);
            set_ANCOUNT(&(ans.header), 1);

            ans.answers = &ans_r;
            snd_len = send_format_msg(&ans, ans_buff);
            printf("sle\n");
            if(sendto(sock, ans_buff, snd_len, 0,
        		(struct sockaddr *) &multicast_addr,
        		sizeof(multicast_addr)) != snd_len) {
              fprintf(stderr, "nie udalo sie odpowiedziec :c\n");
            }

          }
        }
      }
      else {//if (get_QR(&(rcv.header)) == QR_RESPONSE)
        printf("odpowiedz\n");
      }
    }
    clean_msg(&rcv);

}


int main (int argc, char **argv) {
  struct event_base *main_loop;
  evutil_socket_t delay_sock, multicast_sock;
  struct event *udp_client_event, *multicast_listener_event, *signal_event;
  opterr = 0;

  int opt;
  while ((opt = getopt (argc, argv, "u:U:t:T:v:s")) != -1) {
    switch (opt) {
      case 'u':
        delay_port = atoi(optarg);
        if(!delay_port) {
          fprintf(stderr, "bledny port opoznien\n");
          return 1;
        }
        break;
      case 'U':
        ui_port = atoi(optarg);
        if(!ui_port) {
          fprintf(stderr, "bledny port telnetu\n");
          return 1;
        }
        break;
      case 't':
        delay_ref = atof(optarg);
        if(delay_ref == 0.0) {
          fprintf(stderr, "bledny czas pomiedzy mierzeniem opoznien\n");
          return 1;
        }
        break;
      case 'T':
        discovery_ref = atof(optarg);
        if(discovery_ref == 0.0) {
          fprintf(stderr, "bledny czas pomiedzy odkrywaniem komputerow\n");
          return 1;
        }
        break;
      case 'v':
        ui_ref = atof(optarg);
        if(ui_ref == 0.0) {
          fprintf(stderr, "bledny czas pomiedzy odkrywaniem odswierzaniem ui\n"
          );
          return 1;
        }
      case 's':
        ssh_tcp = 1;
        break;
      default:
        fprintf(stderr, "bledna opcja\n");
        return 1;
    }
  }

  init_ip();
  init_mdns(ssh_tcp);
  main_loop = event_base_new();
  delay_sock = get_delay_sock();
  multicast_sock = get_multi_sock();

  udp_client_event = event_new(main_loop, delay_sock, EV_READ|EV_PERSIST,
                               udp_delays_ans_cb, NULL);
  if(!udp_client_event) {
    fprintf(stderr, "nie udalo sie utworzyc eventu clienta udp\n");
    perror("");
    exit(-1);
  }

  if(event_add(udp_client_event, NULL) == -1) {
    fprintf(stderr, "nie udalo sie przylaczyc eventu clienta udp\n");
    exit(-1);
  }


  multicast_listener_event = event_new(main_loop, multicast_sock,
      EV_READ|EV_PERSIST, multicast_rcv_cb, NULL);
  if(!multicast_listener_event)  {
    fprintf(stderr, "nie udalo sie utworzyc eventu clienta multicast\n");
    exit(-1);
  }

  if(event_add(multicast_listener_event, NULL) == -1) {
    fprintf(stderr, "nie udalo sie przylaczyc eventu clienta multicast\n");
    exit(-1);
  }

  signal_event = evsignal_new(main_loop, SIGINT, sigint_cb, (void *)main_loop);

	if (!signal_event || event_add(signal_event, NULL)<0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return 1;
	}

  if(event_base_dispatch(main_loop) == -1) {
    fprintf(stderr, "nie udalo sie uruchomic glownej petli\n");
    exit(-1);
  }

  event_free(signal_event);
  event_free(multicast_listener_event);
  event_free(udp_client_event);
  event_base_free(main_loop);

  close(delay_sock);
  close(multicast_sock);

  return 0;
}
