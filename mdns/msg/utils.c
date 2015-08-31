#include "utils.h"
#include "limits.h"


int unit16_to_send(uint16_t num, char * buff) {
  uint16_t tmp = num;

  tmp >>= 8;

  *buff = (unsigned char) (tmp & 0x00FF);
  buff++;

  *buff = (unsigned char) (num & 0x00FF);

  return 2;
}


int unit32_to_send(uint32_t num, char * buff) {
  *buff = (unsigned char) ((num >> 24) & 0x000000FF);
  buff++;

  *buff = (unsigned char) ((num >> 16) & 0x000000FF);
  buff++;

  *buff = (unsigned char) ((num >> 8) & 0x000000FF);
  buff++;

  *buff = (unsigned char) (num & 0x000000FF);

  return 4;
}


uint16_t get_uint16_t(char * buff) {
  return ((((uint16_t) buff[0]) & 0x00FF) << 8) |
         (((uint16_t)buff[1]) & 0x00FF);
}


uint32_t get_uint32_t(char * buff) {
  return ((((uint32_t) buff[0]) & 0x000000FF) << 24) |
         ((((uint32_t) buff[1]) & 0x000000FF) << 16) |
         ((((uint32_t) buff[2]) & 0x000000FF) << 8)  |
          (((uint32_t) buff[3]) & 0x000000FF);
}


int get_NAME_from_net(char * dest, char * buff, int max_size, char * full_msg) {

  char c = buff[0], i = 0;
  int j = 0, length;

  length = 1;
  if(max_size == 0)
    return -1;
  dest[j] = *buff;
  buff++;
  j++;
  max_size--;
  uint16_t ptr;

  while(c) {
    for(i = 0; i < c; ++i) {
      if(max_size == 0)
        return -1;
      dest[j] = *buff;
      buff++;
      j++;
      length += 1;
      max_size--;
    }
    if(max_size == 0)
      return -1;
    c = *buff;

    while ((c & 0x80) && (c & 0x40)) {
      ptr= get_uint16_t(buff);
      ptr &= 0x3FFF;
      max_size += (buff - full_msg);
      buff = full_msg + ptr;
      c = *buff;
    }

    dest[j] = *buff;
    buff++;
    j++;
    length += 1;
    max_size--;
  }
  return length;
}

int domain_to_NAME(char * NAME, const char * domain) {
  int i = 0;
  char l_size = 0;
  char * s = NAME;

  while(1) {
    while(domain[i + l_size] != '.' && domain[i + l_size] != '\0') {
      l_size++;
      if (l_size > DNS_Q_QLABEL_MAX_LENGTH)
        return -1;
    }

    *s = l_size;
    s++;

    while (l_size) {
      if (i >= DNS_Q_QNAME_MAX_LENGTH)
        return -1;
      *s = domain[i];
      i++;
      s++;
      l_size--;
    }
    if (domain[i] == '.')
      i++;
    if (domain[i] == '\0') {
      *s = domain[i];
      break;
    }
  }
  return s - NAME + 1;
}
