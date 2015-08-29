#ifndef MDNS_MSG_LIMITS
#define MDNS_MSG_LIMITS

#define DNS_Q_QNAME_MAX_LENGTH 255 // liczac '\0' na koncu w RFC 6762 niby pisze
                                   // ze powinno byc liczone bez '\0'
                                   // ale w dodatku C jest taki oto fragment
                                   // "many Unicast DNS implementers have read
                                   // these RFCs differently,"
                                   // dodatkowo ta stala bedzie uzywana jedynie
                                   // podczas zamiany normalnej nawzy (www.a.pl)
                                   // (jesli w ogole to bede robic)
                                   // wiec wole nie pozwolic na cos co nie
                                   // zawsze musi zostac obsluzone
#define DNS_Q_QLABEL_MAX_LENGTH 63

#define DNS_R_NAME_MAX_LENGTH  DNS_Q_QNAME_MAX_LENGTH
#define DNS_R_LABEL_MAX_LENGTH DNS_Q_QLABEL_MAX_LENGTH
#define DNS_R_DATA_MAX_LENGTH 65535 // rfc 6763  6.1

#endif
