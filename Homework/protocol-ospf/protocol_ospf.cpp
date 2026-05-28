#include "protocol_ospf.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

OspfErrorCode parse_ip(const uint8_t *packet, uint32_t len,
                       const uint8_t **lsa_start, int *lsa_num) {
  // TODO
  if (len < sizeof(struct ip6_hdr)) {
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  const struct ip6_hdr *ip6 = (const struct ip6_hdr *) packet;
  if (ntohs(ip6->ip6_plen) != len - sizeof(struct ip6_hdr)) {
    return OspfErrorCode::ERR_BAD_LENGTH;
  }

  if (ip6->ip6_nxt != 89) {
    return OspfErrorCode::ERR_IPV6_NEXT_HEADER_NOT_OSPF;
  }

  if (len - sizeof(struct ip6_hdr) < sizeof(struct ospf_header)) {
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  const ospf_header *ospf =
      (const ospf_header *) &packet[sizeof(struct ip6_hdr)];
  if (ntohs(ospf->length) != len - sizeof(struct ip6_hdr)) {
    return OspfErrorCode::ERR_BAD_LENGTH;
  }

  if (ospf->type != OSPF_LSU) {
    return OspfErrorCode::ERR_OSPF_NOT_LSU;
  }

  if (len < sizeof(struct ip6_hdr) + sizeof(struct ospf_lsu_header)) {
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  const ospf_lsu_header *lsu =
      (const ospf_lsu_header *) &packet[sizeof(struct ip6_hdr)];
  *lsa_num = ntohl(lsu->num_lsas);
  *lsa_start = packet + sizeof(struct ip6_hdr) + sizeof(struct ospf_lsu_header);

  return OspfErrorCode::SUCCESS;
}

OspfErrorCode disassemble(const uint8_t *lsa, uint16_t buf_len, uint16_t *len,
                          RouterLsa *output) {
  // TODO
  const ospf_lsa_header *lsa_head = (ospf_lsa_header *) lsa;
  if (buf_len < sizeof(struct ospf_lsa_header)) {
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  if (buf_len < ntohs(lsa_head->length)) {
    return OspfErrorCode::ERR_PACKET_TOO_SHORT;
  }

  *len = ntohs(lsa_head->length);

  if (ntohs(lsa_head->length) < sizeof(ospf_lsa_header)) {
    return OspfErrorCode::ERR_LSA_LENGTH;
  }

  if (ospf_lsa_checksum((struct ospf_lsa_header *) lsa_head, ntohs(lsa_head->length)) != 0) {
    return OspfErrorCode::ERR_LSA_CHECKSUM;
  }

  if (ntohs(lsa_head->ls_age) > LSA_MAX_AGE) {
    return OspfErrorCode::ERR_LS_AGE;
  }

  if (ntohl(lsa_head->ls_sequence_number) == RESERVED_LS_SEQ) {
    return OspfErrorCode::ERR_LS_SEQ;
  }

  if (ntohs(lsa_head->ls_type) != 0x2001) {
    return OspfErrorCode::ERR_LSA_NOT_ROUTER;
  }

  if (ntohs(lsa_head->length) < sizeof(struct ospf_lsa_header) + 4) {
    return OspfErrorCode::ERR_ROUTER_LSA_LENGTH;
  }

  uint16_t lsa_len = ntohs(lsa_head->length);
  uint16_t fixed_len = sizeof(struct ospf_lsa_header) + 4;

  if ((lsa_len - fixed_len) % sizeof(struct ospf_router_lsa_entry) != 0) {
    return ERR_ROUTER_LSA_LENGTH;
  }

  int entry_num = (lsa_len - fixed_len) / sizeof(struct ospf_router_lsa_entry);
  const struct ospf_router_lsa_entry *entries =
      (const struct ospf_router_lsa_entry *)(lsa + fixed_len);

  for (int i = 0; i < entry_num; i++) {
    const struct ospf_router_lsa_entry *entry = &entries[i];
    if (entry->type > 4 || entry->type < 1) {
      return OspfErrorCode::ERR_ROUTER_LSA_ENTRY_TYPE;
    }
  }

  for (int i = 0; i < entry_num; i++) {
    const struct ospf_router_lsa_entry *entry = &entries[i];
    if (entry->zero != 0) {
      return OspfErrorCode::ERR_BAD_ZERO;
    }
  }

  const struct ospf_router_lsa *router_lsa =
      (const struct ospf_router_lsa *) lsa;
  output->ls_age = ntohs(lsa_head->ls_age);
  output->link_state_id = ntohl(lsa_head->link_state_id);
  output->advertising_router = ntohl(lsa_head->advertising_router);
  output->ls_sequence_number = ntohl(lsa_head->ls_sequence_number);
  output->flags = router_lsa->flags;
  output->zero = router_lsa->zero;
  output->options = ntohs(router_lsa->options);
  output->entries.clear();

  for (int i = 0; i < entry_num; i++) {
    const struct ospf_router_lsa_entry *entry = &entries[i];

    RouterLsaEntry out_entry;
    out_entry.type = entry->type;
    out_entry.metric = ntohs(entry->metric);
    out_entry.interface_id = ntohl(entry->interface_id);
    out_entry.neighbor_interface_id = ntohl(entry->neighbor_interface_id);
    out_entry.neighbor_router_id = ntohl(entry->neighbor_router_id);

    output->entries.push_back(out_entry);
  }
  return OspfErrorCode::SUCCESS;
}
