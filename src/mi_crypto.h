#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace mi {

struct KeyPair {
  uint8_t d[32];
};

struct Keychain {
  uint8_t app[32];
  uint8_t dev[32];
};

inline bool gen_keypair(KeyPair&, uint8_t pub[64]) {
  if (!pub) return false;
  memset(pub, 0, 64);
  return true;
}

inline bool calc_did(const KeyPair&, const uint8_t*, const uint8_t*, size_t, uint8_t did[72], size_t* dl, uint8_t token[12]) {
  if (!did) return false;
  memset(did, 0, 72);
  if (dl) *dl = 0;
  if (token) memset(token, 0, 12);
  return true;
}

inline bool calc_login(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t info[32], uint8_t expct[32], Keychain&) {
  if (!info || !expct) return false;
  memset(info, 0, 32);
  memset(expct, 0, 32);
  return true;
}

inline int decrypt_uart(const uint8_t key[32], const uint8_t* in, size_t len, uint8_t* out) {
  (void)key;
  if (!in || !out || len > 256) return -1;
  memcpy(out, in, len);
  return (int)len;
}

inline size_t encrypt_uart(const uint8_t key[32], const uint8_t* in, size_t len, uint8_t, const uint8_t*, uint8_t* out) {
  (void)key;
  if (!in || !out || len > 256) return 0;
  memcpy(out, in, len);
  return len;
}

}  // namespace mi
