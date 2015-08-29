#include "utils.h"


int unit16_to_send(uint16_t num, char * buff) {
  uint16_t tmp = num;

  tmp >>= 8;

  *buff = (char) (tmp & 0x00FF);
  buff++;

  *buff = (char) (num & 0x00FF);

  return 2;
}


int unit32_to_send(uint32_t num, char * buff) {
  *buff = (char) ((num >> 24) & 0x000000FF);
  buff++;

  *buff = (char) ((num >> 16) & 0x000000FF);
  buff++;

  *buff = (char) ((num >> 8) & 0x000000FF);
  buff++;

  *buff = (char) (num & 0x000000FF);

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
