#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint32_t calc_sum(char *buffer, uint32_t size) {
  uint32_t sum = 0;
  uint32_t i = 0;
  for (i = 0; i < size; i += 2) {
    uint16_t number = ((uint8_t) buffer[i] << 8) + (uint8_t) buffer[i + 1];
    sum += number;
  }

  while (sum >= (1 << 16)) {
    uint32_t lower = sum & (0x0000FFFF);
    uint32_t upper = sum >> 16;
    sum = lower + upper;
  }

  return sum;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *) packet;

  bool correct;
  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *) &packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum
    size_t packet_size = len - sizeof(struct ip6_hdr);
    size_t buf_size = 40 + packet_size + (packet_size % 2 ? 1 : 0);

    /* check whether current checksum is right */
    char pseudo_header[40] = {};
    memcpy(pseudo_header, &(ip6->ip6_src), sizeof(char) * 16);
    memcpy(pseudo_header + 16, &(ip6->ip6_dst), sizeof(char) * 16);
    uint32_t udp_len = htonl(ntohs(udp->uh_ulen));

    memcpy(pseudo_header + 32, &udp_len, sizeof(char) * 4);
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = 17;

    char *buffer = (char *) malloc(sizeof(char) * buf_size);
    memset(buffer, 0, sizeof(char) * buf_size);
    memcpy(buffer, pseudo_header, sizeof(char) * 40);
    memcpy(buffer + 40, udp, sizeof(char) * packet_size);

    uint32_t sum = calc_sum(buffer, packet_size + 40);
    correct = (sum == 0xFFFF);

    /* calc the right one */
    if (udp->check == 0) {
      correct = false;
    }
    udp->check = 0;
    memcpy(buffer + 40, udp, sizeof(char) * packet_size);
    sum = calc_sum(buffer, buf_size);
    if ((sum & 0x0000FFFF) == 0x0000FFFF) {
      sum = 0;
    }
    udp->check = htons(~sum);
    free(buffer);
  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *) &packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
    size_t packet_size = len - sizeof(struct ip6_hdr);
    size_t buf_size = 40 + packet_size + (packet_size % 2 ? 1 : 0);

    /* check whether current checksum is right */
    char pseudo_header[40] = {};
    memcpy(pseudo_header, &(ip6->ip6_src), sizeof(char) * 16);
    memcpy(pseudo_header + 16, &(ip6->ip6_dst), sizeof(char) * 16);
    uint32_t icmp_len = htonl(len - sizeof(struct ip6_hdr));
    memcpy(pseudo_header + 32, &icmp_len, sizeof(char) * 4);
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = 58;

    char *buffer = (char *) malloc(sizeof(char) * buf_size);
    memset(buffer, 0, sizeof(char) * buf_size);
    memcpy(buffer, pseudo_header, sizeof(char) * 40);
    memcpy(buffer + 40, icmp, sizeof(char) * packet_size);

    uint32_t sum = calc_sum(buffer, packet_size + 40);
    correct = (sum == 0xFFFF);

    /* calc the right one */
    icmp->icmp6_cksum = 0;
    memcpy(buffer + 40, icmp, sizeof(char) * packet_size);
    sum = calc_sum(buffer, buf_size);

    icmp->icmp6_cksum = htons(~sum);

    free(buffer);
  } else {
    assert(false);
  }

  return correct;
}
