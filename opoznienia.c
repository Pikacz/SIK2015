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


#include "mdns/msg/utils.h"
#include "mdns/msg/msg.h"
#include "mdns/mdns.h"
#include "mdns/msg/globals.h"

#define MULTICAST_PORT 5353
#define MULTICAST_IP "224.0.0.251"

#define MDNS_MAX_LEN 30000

#define MAX_IPS 100000

#define NAME_MLENGTH 300

static uint32_t my_ip;

// odstep sekundowy odswierzania opoznien, odkrywania komputerow, ui
double delay_ref = 1, discovery_ref = 10, ui_ref = 1;
struct timeval del_tv, disc_tv, ui_tv;
// port udp opoznien, tcp telnetu
int delay_port = 3382, ui_port = 3637;
// czy rozglaszamy tcp
int ssh_tcp = 0;

char TCP_SERV[200], UDP_SERV[200];

struct event_base *main_loop;
struct sockaddr_in multicast_addr;


typedef struct _delay_t{
    int32_t udp_delay[10];
    int32_t tcp_delay[10];
    int32_t icmp_delay[10];
    struct event *ev[3]; // 0 - udp, 1 - tcp, 2 - icmp
    uint32_t ip;
    int udp_i, tcp_i;

} delay_t;


static delay_t found_ips[MAX_IPS];
static char * found_UDP[MAX_IPS], * found_TCP[MAX_IPS];
int ips_size = 0;


typedef struct con_desc con_desc_t;



uint64_t current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL);
    uint64_t useconds = te.tv_sec*1000000LL + te.tv_usec;
    return useconds;
}


void init_data() {
  memset(found_ips, 0, sizeof(found_ips));
  memset(found_UDP, 0, sizeof(found_UDP));
  memset(found_TCP, 0, sizeof(found_TCP));
  int tmp;

  delay_ref *= 1000;
  tmp = delay_ref;
  del_tv.tv_sec = tmp / 1000; del_tv.tv_usec = tmp % 1000;

  discovery_ref *= 1000;
  tmp = discovery_ref;
  disc_tv.tv_sec = tmp / 1000; disc_tv.tv_usec = tmp % 1000;

  ui_ref *= 1000;
  tmp = ui_ref;
  ui_tv.tv_sec = tmp / 1000; ui_tv.tv_usec = tmp % 1000;
  domain_to_NAME(UDP_SERV, "_opoznienia._udp.local.");
  domain_to_NAME(TCP_SERV, "_ssh._tcp.local.");
}

void init_ip() {
  // nie bylem w stanie znalezc sensownej funkcji zwracajacej moje ip
  // znalzalem mozliwosc iteracji po interfejsach i magicznego zgadywania
  // somyslnego interfejsu
  // innym bylo przeczytanie pliku /proc/net/route
  // otworzenie polaczenia tcp uznalem za najsensowniejsze i najbezpieczniejsze
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
    if ((bind(sock, (struct sockaddr *) &multicast_addr,
              sizeof(multicast_addr))) < 0) {
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
	printf("Papa :*\n");
  int i;
  for(i = 0; i < MAX_IPS; ++i) {
    if (found_UDP[i])
      free(found_UDP[i]);
    if (found_TCP[i])
      free(found_TCP[i]);
  }
	event_base_loopexit((struct event_base *) arg, NULL);
}

void udp_delays_ans_cb(evutil_socket_t sock, short ev, void *arg) {
  static uint64_t udp_delays_buff[2];
  struct sockaddr_in client_address;
  socklen_t rcva_len;
  ssize_t len;

  len = recvfrom(sock, (char *)udp_delays_buff, sizeof(uint64_t), 0,
      (struct sockaddr *) &client_address, &rcva_len);
  if (len != sizeof(uint64_t))
    return; // miala byc liczba 64 bitowa, nie musze zachowywac jakiejs
            // smiesznej zgodnosci
  udp_delays_buff[1] = htobe64(current_timestamp());
  sendto(sock, udp_delays_buff, 2 * sizeof(uint64_t), 0,
      (struct sockaddr *) &client_address, rcva_len);
  // nie dalo sie wyslac, coz zyje sie dalej :p
}

void udp_delays_save_cb(evutil_socket_t sock, short ev, void *arg) {
  int id = * (int*) arg;
  int i;
  static uint64_t buffer[2], res;
  struct sockaddr_in address;
  socklen_t alen;

  int len = recvfrom(sock, buffer, 2 * sizeof(uint64_t), 0,
      (struct sockaddr *) &address, &alen);
  if(len != 2 * sizeof(uint64_t)) {
    res = 0;
  }
  else {
    res = be64toh(buffer[1]) - be64toh(buffer[0]);
  }
  for(i = 0; i < 9; ++i)
    found_ips[id].udp_delay[i] = found_ips[id].udp_delay[i + 1];
  found_ips[id].udp_delay[9] = res;
  close(sock);
  printf("udp save %d\n", id);
}

void udp_delays_ask_cb(evutil_socket_t sock, short ev, void *arg) {
  int id = * (int*) arg;
  printf("delay ask %d\n", id);
  struct sockaddr_in my_address;
  static uint64_t buffer[1];
  my_address.sin_family = AF_INET; // IPv4
	my_address.sin_addr.s_addr = htonl(found_ips[id].ip);
  my_address.sin_port = htons(delay_port);
  int i;




  int len, soc;

  soc = socket(AF_INET, SOCK_DGRAM, 0);

  buffer[0] = htobe64(current_timestamp());
	len = sendto(soc, (void*)buffer, sizeof(uint64_t), 0,
		(struct sockaddr *) &my_address, sizeof(my_address));

	if (len != sizeof(uint64_t)) {
		free(found_UDP[found_ips[id].udp_i]);
    found_UDP[found_ips[id].udp_i] = NULL;
    event_free(found_ips[id].ev[0]);
    found_ips[id].ev[0] = NULL;
    for(i = 0; i < 10; ++i)
      found_ips[id].udp_delay[i] = 0;
	}
  else

  event_add(event_new(main_loop, soc, EV_READ, udp_delays_save_cb, arg),NULL);

}


void tcp_delay_cb(evutil_socket_t sock, short ev, void *arg) {
  printf("delayy cb\n");
//   int sock, id = *((int*)arg);
// 	struct sockaddr_in server_address;
//
// 	int err;
// 	uint64_t time1, time2;
//
//
//   // 'converting' host/port in string to struct addrinfo
// 	memset(&addr_hints, 0, sizeof(struct addrinfo));
// 	addr_hints.ai_family = AF_INET; // IPv4
// 	addr_hints.ai_socktype = SOCK_STREAM;
// 	addr_hints.ai_protocol = IPPROTO_TCP;
// 	err = getaddrinfo(host, port, &addr_hints, &addr_result);
// 	if (err != 0)
// 		syserr("getaddrinfo: %s\n", gai_strerror(err));
//
// 	// initialize socket according to getaddrinfo results
// 	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//
//   server_address.sin_family = AF_INET; // IPv4
//   server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
//   server_address.sin_port = htons(22);
//
//   if (sock < 0)
//     return;
//
// DUPA
//
//
// 	time1 = current_timestamp();
// 	// connect socket to the server
// 	if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
// 		syserr("connect");
// 	time2 = current_timestamp();
//
// 	freeaddrinfo(addr_result);
//
//
//
// 	(void) close(sock); // socket would be closed anyway when the program ends
//
// 	(void) printf("%" PRIu64 " %" PRIu64 "\n", time1, time2);
}

void multicast_rcv_cb(evutil_socket_t sock, short ev, void *arg) {
    static char rcv_buff[MDNS_MAX_LEN], ans_buff[MDNS_MAX_LEN];
    static struct sockaddr_in from_addr;
    static int rcv_len, snd_len;
    static unsigned int from_len;
    static dns_msg_t rcv, ans;
    static dns_resource_t ans_r;
    static dns_question_t ans_q;
    static int i, j, jj, fnd, asknm;
    static char * tmp_buff;
    uint32_t rcv_ip;

    init_msg(&rcv);



    memset(rcv_buff, 0, sizeof(rcv_buff));
    memset(&from_addr, 0, sizeof(from_addr));


    if ((rcv_len = recvfrom(sock, rcv_buff, MDNS_MAX_LEN, 0,
      (struct sockaddr*)&from_addr, &from_len)) < 0) {
        return;
    }

    printf("Received %d bytes from %s: ", rcv_len,
           inet_ntoa(from_addr.sin_addr));
    fflush(stdout);
    if(message_from_network(&rcv, rcv_buff, MDNS_MAX_LEN) < 0) {
      printf("bledna wiadomosc\n");
    }
    else if(get_QR(&(rcv.header)) == QR_QUERY) {
      printf("pytanie %d\n", get_QDCOUNT(&(rcv.header)));
      for(i = 0; i < get_QDCOUNT(&(rcv.header)); ++i) {
        if(answer(rcv.questions + i, &ans_r, my_ip) == 0) {
          //potrafie odpowiedziec
          init_msg(&ans);
          set_QR(&(ans.header), QR_RESPONSE);
          set_ANCOUNT(&(ans.header), 1);

          ans.answers = &ans_r;
          snd_len = send_format_msg(&ans, ans_buff);

          if(sendto(sock, ans_buff, snd_len, 0, // TODO unicast
      		    (struct sockaddr *) &multicast_addr,
      		    sizeof(multicast_addr)) != snd_len) {
            fprintf(stderr, "nie udalo sie odpowiedziec na A :c\n");
          }
        }
      }
    }
    else {//if (get_QR(&(rcv.header)) == QR_RESPONSE)

        for(i = 0; i < get_ANCOUNT(&(rcv.header)); ++i) {

          if (is_rA(rcv.answers + i)) {
            printf("odpowiedz zawierajaca ip\n");
            for(jj = 0; jj < 4; ++jj){
              printf("%u ", rcv.answers[i].RDATA[jj]);
            }
            printf("\n");
            rcv_ip = ntohl (*((uint32_t *)rcv.answers[i].RDATA));

            if (names_equal(rcv.answers[i].NAME + rcv.answers[i].NAME[0] + 1,
                            UDP_SERV)) {


              for(j = 0; j < MAX_IPS; ++j) {
                if (names_equal(found_UDP[j], rcv.answers[i].NAME))
                  break;
              }

              if (j == MAX_IPS)
                continue;

              for(jj = 0; jj < MAX_IPS; ++jj) {
                if (found_ips[jj].ip == rcv_ip)
                  break;
              }
              if (jj == MAX_IPS) {
                for(jj = 0; jj < MAX_IPS; ++jj)
                  if(!found_ips[jj].ip) {
                      found_ips[jj].ip = rcv_ip;
                      break;
                  }
              }
              if (jj == MAX_IPS)
               continue; // no bez przesady to sie nie zdarzy

              if(found_ips[jj].ev[0])
                continue;
              found_ips[jj].udp_i = j;
              found_ips[jj].ev[0] = event_new(main_loop, -1,
                  EV_TIMEOUT | EV_PERSIST, udp_delays_ask_cb, (void*) &jj);

              event_add(found_ips[jj].ev[0], &del_tv);
            } else if (names_equal(
              rcv.answers[i].NAME + rcv.answers[i].NAME[0] + 1,
              UDP_SERV)) {

              for(j = 0; j < MAX_IPS; ++j) {
                if (names_equal(found_TCP[j], rcv.answers[i].NAME))
                  break;
              }
              if (j == MAX_IPS)
               continue; //ta nazwa jeszcze nigdy nie byla szukana

              for(jj = 0; jj < MAX_IPS; ++jj) {
                if (found_ips[jj].ip == rcv_ip)
                  break;
              }
              if (jj == MAX_IPS) {
                for(jj = 0; jj < MAX_IPS; ++jj)
                  if(!found_ips[jj].ip) {
                      found_ips[jj].ip = rcv_ip;
                      break;
                  }
              }
              if (jj == MAX_IPS)
                continue; // no bez przesady to sie nie zdarzy



              if(found_ips[jj].ev[0])
                continue;
              found_ips[jj].tcp_i = j;
              found_ips[jj].ev[1] = event_new(main_loop, -1,
                  EV_TIMEOUT | EV_PERSIST, tcp_delay_cb, (void*) &jj);

              event_add(found_ips[jj].ev[0], &del_tv);


            }
          }
          else if (is_rPTR(rcv.answers + i)) {
            asknm = 0;
            if(rPTR_my_name(rcv.answers + i, rcv_buff))
              continue; // zmien nazwe komputera

            tmp_buff = (char *) malloc(sizeof(char) * NAME_MLENGTH);
            memset(tmp_buff, 0, sizeof(char) * NAME_MLENGTH);
            get_NAME_from_net(tmp_buff, rcv.answers[i].RDATA,
                              rcv.answers[i].RDLENGTH, rcv_buff);
            if(rPTR_UDP(rcv.answers + i, rcv_buff)) {
              asknm = 1;
              fnd = 0;
              for(j = 0; j < MAX_IPS; ++j){
                if(found_UDP[i]) {
                  if (names_equal(found_UDP[j], tmp_buff)){
                    fnd = 1;
                    asknm = 0;
                    break;
                  }
                }
              }

              for(j = 0; !fnd && (j < MAX_IPS); ++j) {
                if (found_UDP[j] == NULL)
                  break;
              }
              if(j >= MAX_IPS || fnd)
                free(tmp_buff);
              else
                found_UDP[j] = tmp_buff;
            }
            else if(rPTR_TCP(rcv.answers + i, rcv_buff)) {
              fnd = 0;
              asknm = 1;
              for(j = 0; j < MAX_IPS; ++j){
                if(found_TCP[j]) {
                  if (names_equal(found_TCP[j], tmp_buff)){
                    fnd = 1;
                    asknm = 0;
                    break;
                  }
                }
              }

              for(j = 0; !fnd && (j < MAX_IPS); ++j) {
                if (found_TCP[j] == NULL)
                  break;
              }
              if(j >= MAX_IPS || fnd)
                free(tmp_buff);
              else
                found_TCP[j] = tmp_buff;
            }
            else free(tmp_buff);
            if(asknm) {
              ask_A(tmp_buff, &ans_q);
              init_msg(&ans);
              set_QR(&(ans.header), QR_QUERY);
              set_QDCOUNT(&(ans.header), 1);

              ans.questions = &ans_q;
              snd_len = send_format_msg(&ans, ans_buff);

              if(sendto(sock, ans_buff, snd_len, 0,
          		    (struct sockaddr *) &multicast_addr,
          		    sizeof(multicast_addr)) != snd_len) {
                    fprintf(stderr, "nie udalo sie zapytc o A :c\n");
              }
            }
          }

        }
      }

      clean_msg(&rcv);



}


void multicast_discover_cb(evutil_socket_t sock, short ev, void *arg) {
  static char q_buff[MDNS_MAX_LEN];
  static int snd_len;
  static dns_msg_t msgq;
  static dns_question_t q;

  ask_PTR(UDP_SERV, &q);
  init_msg(&msgq);
  set_QR(&(msgq.header), QR_QUERY);
  set_QDCOUNT(&(msgq.header), 1);

  msgq.questions = &q;
  snd_len = send_format_msg(&msgq, q_buff);

  if(sendto(sock, q_buff, snd_len, 0, (struct sockaddr *) &multicast_addr,
            sizeof(multicast_addr)) != snd_len) {
    fprintf(stderr, "nie udalo sie zapytc o PTR :c\n");
  }

  ask_PTR(TCP_SERV, &q);
  init_msg(&msgq);
  set_QR(&(msgq.header), QR_QUERY);
  set_QDCOUNT(&(msgq.header), 1);

  msgq.questions = &q;
  snd_len = send_format_msg(&msgq, q_buff);

  if(sendto(sock, q_buff, snd_len, 0, (struct sockaddr *) &multicast_addr,
            sizeof(multicast_addr)) != snd_len) {
    fprintf(stderr, "nie udalo sie zapytc o PTR :c\n");
  }
}

int main (int argc, char **argv) {
  evutil_socket_t delay_sock, multicast_sock;
  struct event *udp_client_event, *multicast_listener_event, *signal_event,
               *discover_event;
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

  init_data();
  init_ip();
  init_mdns(ssh_tcp);
  main_loop = event_base_new();
  delay_sock = get_delay_sock();
  multicast_sock = get_multi_sock();

  udp_client_event = event_new(main_loop, delay_sock, EV_READ|EV_PERSIST,
                               udp_delays_ans_cb, NULL);
  if(!udp_client_event) {
    fprintf(stderr, "nie udalo sie utworzyc eventu serwera udp\n");
    exit(-1);
  }

  if(event_add(udp_client_event, NULL) == -1) {
    fprintf(stderr, "nie udalo sie przylaczyc eventu serwera udp\n");
    exit(-1);
  }


  multicast_listener_event = event_new(main_loop, multicast_sock,
      EV_READ|EV_PERSIST, multicast_rcv_cb, NULL);
  if(!multicast_listener_event)  {
    fprintf(stderr, "nie udalo sie utworzyc eventu serwera multicast\n");
    exit(-1);
  }

  if(event_add(multicast_listener_event, NULL) == -1) {
    fprintf(stderr, "nie udalo sie przylaczyc eventu serwera multicast\n");
    exit(-1);
  }

  discover_event = event_new(main_loop, multicast_sock, EV_TIMEOUT|EV_PERSIST,
                    multicast_discover_cb, NULL);

  if(!discover_event || event_add(discover_event, &disc_tv) < 0) {
    fprintf(stderr, "odkrywnie nie uruchomilo sie\n");
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
