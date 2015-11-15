#ifndef MLVPN_TIMESTAMP_H
#define MLVPN_TIMESTAMP_H

#include <stdint.h>
#include <ev.h>


uint64_t
mlvpn_timestamp64(ev_tstamp now);

uint16_t
mlvpn_timestamp16(uint64_t now);

uint16_t
mlvpn_timestamp16_diff(uint16_t tsnew, uint16_t tsold);

#endif