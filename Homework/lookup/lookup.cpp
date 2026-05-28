#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

std::vector<RoutingTableEntry> RoutingTable;

void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  bool found = false;
  std::vector<RoutingTableEntry>::iterator it;
  for (it = RoutingTable.begin(); it != RoutingTable.end(); ++it) {
    if (it->len == entry.len && it->addr == entry.addr) {
      found = true;
      break;
    }

    if (entry.addr < it->addr) {
      break;
    }
  }

  if (!found) {
    if (!insert) {
      /* Fail to delete */
      return;
    } else {
      RoutingTable.insert(it, entry);
    }
  } else {
    if (!insert) {
      RoutingTable.erase(it);
    } else {
      *it = entry;
    }
  }
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  std::vector<RoutingTableEntry>::iterator it;
  std::vector<RoutingTableEntry>::iterator max_prefix_entry;
  int maxlen = 0;
  bool found = false;
  for (it = RoutingTable.begin(); it != RoutingTable.end(); ++it) {
    in6_addr mask = len_to_mask(it->len);
    if ((addr & mask) == it->addr) {
      if (!found || it->len > maxlen) {
        maxlen = it->len;
        max_prefix_entry = it;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *if_index = max_prefix_entry->if_index;
  *nexthop = max_prefix_entry->nexthop;
  return true;
}

int mask_to_len(const in6_addr mask) {
  // TODO
  /* find the pos */
  int i;
  int pos;
  for (pos = 0; pos <= 127; ++pos) {
    size_t byte = (pos >> 3);
    size_t offset = (pos - ((pos >> 3) << 3));
    if (((mask.s6_addr[byte] >> (7 - offset)) & 1) == 0) {
      break;
    }
  }

  /* check */
  int j;
  for (j = 0; j < pos; ++j) {
    size_t byte = (j >> 3);
    size_t offset = (j - ((j >> 3) << 3));
    if (((mask.s6_addr[byte] >> (7 - offset) & 1) != 1)) {
      return -1;
    }
  }

  for (j = pos; j <= 127; ++j) {
    size_t byte = (j >> 3);
    size_t offset = (j - ((j >> 3) << 3));
    if (((mask.s6_addr[byte] >> (7 - offset) & 1) != 0)) {
      return -1;
    }
  }


  return pos;
}

in6_addr len_to_mask(int len) {
  // TODO
  in6_addr result;
  memset(result.s6_addr, 0, sizeof(result.s6_addr));
  size_t byte = (len >> 3);
  size_t offset = (len - ((len >> 3) << 3));
  for (int i = 0; i < byte; ++i) {
    result.s6_addr[i] = 0xFF;
  }
  for (int i = 0; i < offset; ++i) {
    result.s6_addr[byte] |= (1 << (7 - i));
  }
  return result;
}
