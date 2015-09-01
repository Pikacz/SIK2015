#include <event2/event.h>
#include <event2/util.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define MULTICAST_PORT 5353
#define MULTICAST_IP "224.0.0.251"

// odstep sekundowy odswierzania opoznien, odkrywania komputerow, ui
double delay_ref = 1, discovery_ref = 10, ui_ref = 1;
// port udp opoznien, tcp telnetu
int delay_port = 3382, ui_port = 3637;
// czy rozglaszamy tcp
int ssh_tcp = 0;



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

void udp_delays_cb(evutil_socket_t sock, short ev, void *arg) {
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


int main (int argc, char **argv) {
  struct event_base *main_loop;
  evutil_socket_t delay_sock;

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


  main_loop = event_base_new();
  delay_sock = get_delay_sock();

  struct event *udp_client_event =
    event_new(main_loop, delay_sock, EV_READ|EV_PERSIST, udp_delays_cb, NULL);
  if(!udp_client_event) {
    fprintf(stderr, "nie udalo sie utworzyc eventu servera udp\n");
    exit(-1);
  }

  if(event_add(udp_client_event, NULL) == -1) {
    fprintf(stderr, "nie udalo sie przylaczyc eventu servera udp\n");
    exit(-1);
  }

  if(event_base_dispatch(main_loop) == -1) {
    fprintf(stderr, "nie udalo sie uruchomic glownej petli\n");
    exit(-1);
  }

  event_free(udp_client_event);
  event_base_free(main_loop);

  return 0;
}
