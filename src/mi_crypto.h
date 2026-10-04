// Xiaomi "mible" registration/login crypto + encrypted UART framing.
// Port of the algorithms in the open-source macbury/m365 (Rust) reference.
// Requires mbedtls (bundled with the ESP32 Arduino core).
//
// Before including, define:   #define MI_FILL_RANDOM(buf, len)   (fills len random bytes)
#pragma once
#include <stdint.h>
#include <string.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/ccm.h>

#ifndef MI_FILL_RANDOM
#error "define MI_FILL_RANDOM(buf,len) before including mi_crypto.h"
#endif

namespace mi {

static int rng(void*, unsigned char* b, size_t n) { MI_FILL_RANDOM(b, n); return 0; }

struct EncKey { uint8_t key[16]; uint8_t iv[4]; };
struct Keychain { EncKey dev; EncKey app; };

// ---------- primitives ----------
inline bool hmac256(const uint8_t* key, size_t kl, const uint8_t* d, size_t dl, uint8_t out[32]) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, kl, d, dl, out) == 0;
}

// HKDF-SHA256 (RFC 5869). salt==nullptr -> 32 zero bytes. okm_len <= 64 here.
inline bool hkdf(const uint8_t* salt, size_t sl, const uint8_t* ikm, size_t il,
                 const uint8_t* info, size_t infol, uint8_t* okm, size_t ol) {
  uint8_t zeros[32] = {0}, prk[32];
  if (!salt) { salt = zeros; sl = 32; }
  if (!hmac256(salt, sl, ikm, il, prk)) return false;
  uint8_t t[32], buf[32 + 32 + 1];
  size_t tl = 0, pos = 0;
  for (uint8_t i = 1; pos < ol; i++) {
    size_t bl = 0;
    memcpy(buf, t, tl); bl += tl;
    memcpy(buf + bl, info, infol); bl += infol;
    buf[bl++] = i;
    if (!hmac256(prk, 32, buf, bl, t)) return false;
    tl = 32;
    size_t c = (ol - pos < 32) ? ol - pos : 32;
    memcpy(okm + pos, t, c);
    pos += c;
  }
  return true;
}

inline bool ccm_enc(const uint8_t key[16], const uint8_t* nonce, const uint8_t* aad, size_t al,
                    const uint8_t* in, size_t n, uint8_t* out /* n+4 */) {
  mbedtls_ccm_context c; mbedtls_ccm_init(&c);
  bool ok = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128) == 0 &&
            mbedtls_ccm_encrypt_and_tag(&c, n, nonce, 12, aad, al, in, out, out + n, 4) == 0;
  mbedtls_ccm_free(&c);
  return ok;
}

inline bool ccm_dec(const uint8_t key[16], const uint8_t* nonce, const uint8_t* aad, size_t al,
                    const uint8_t* in, size_t n /* incl tag */, uint8_t* out) {
  if (n < 4) return false;
  mbedtls_ccm_context c; mbedtls_ccm_init(&c);
  bool ok = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128) == 0 &&
            mbedtls_ccm_auth_decrypt(&c, n - 4, nonce, 12, aad, al, in, out, in + n - 4, 4) == 0;
  mbedtls_ccm_free(&c);
  return ok;
}

// ---------- registration (ECDH P-256) ----------
struct KeyPair {
  mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point Q;
  KeyPair() { mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&Q); }
  ~KeyPair() { mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&Q); }
  KeyPair(const KeyPair&) = delete;
  KeyPair& operator=(const KeyPair&) = delete;
};

// pub64 = X||Y (big endian), i.e. uncompressed point without the 0x04 prefix
inline bool gen_keypair(KeyPair& kp, uint8_t pub64[64]) {
  if (mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) return false;
  if (mbedtls_ecdh_gen_public(&kp.grp, &kp.d, &kp.Q, rng, nullptr) != 0) return false;
  uint8_t b[65]; size_t ol = 0;
  if (mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ol, b, sizeof(b)) != 0 || ol != 65)
    return false;
  memcpy(pub64, b + 1, 64);
  return true;
}

inline bool shared_secret(KeyPair& kp, const uint8_t remote64[64], uint8_t out32[32]) {
  uint8_t b[65]; b[0] = 0x04; memcpy(b + 1, remote64, 64);
  mbedtls_ecp_point Qp; mbedtls_ecp_point_init(&Qp);
  mbedtls_mpi z; mbedtls_mpi_init(&z);
  bool ok = mbedtls_ecp_point_read_binary(&kp.grp, &Qp, b, 65) == 0 &&
            mbedtls_ecp_check_pubkey(&kp.grp, &Qp) == 0 &&
            mbedtls_ecdh_compute_shared(&kp.grp, &z, &Qp, &kp.d, rng, nullptr) == 0 &&
            mbedtls_mpi_write_binary(&z, out32, 32) == 0;
  mbedtls_ecp_point_free(&Qp);
  mbedtls_mpi_free(&z);
  return ok;
}

// remote_info is the parcel received after CMD_GET_INFO; the DID is remote_info[4..].
// did_ct must hold (ri_len - 4 + 4) bytes.
inline bool calc_did(KeyPair& kp, const uint8_t remote64[64], const uint8_t* remote_info, size_t ri_len,
                     uint8_t* did_ct, size_t* did_ct_len, uint8_t token[12]) {
  if (ri_len <= 4) return false;
  uint8_t ss[32], okm[64];
  if (!shared_secret(kp, remote64, ss)) return false;
  static const uint8_t info[] = "mible-setup-info";
  if (!hkdf(nullptr, 0, ss, 32, info, sizeof(info) - 1, okm, 64)) return false;
  memcpy(token, okm, 12);
  const uint8_t* a = okm + 28;  // bytes 12..28 are bind_key (unused)
  static const uint8_t nonce[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};
  static const uint8_t aad[] = "devID";
  size_t n = ri_len - 4;
  if (!ccm_enc(a, nonce, aad, 5, remote_info + 4, n, did_ct)) return false;
  *did_ct_len = n + 4;
  return true;
}

// ---------- login ----------
// my_rand/remote_rand: 16 bytes each. Produces the info hash to send, the hash we expect the
// scooter to have sent, and the session keys.
inline bool calc_login(const uint8_t my_rand[16], const uint8_t remote_rand[16], const uint8_t token[12],
                       uint8_t info_out[32], uint8_t expected_remote[32], Keychain& kc) {
  uint8_t salt[32], salt_inv[32], okm[64];
  memcpy(salt, my_rand, 16);        memcpy(salt + 16, remote_rand, 16);
  memcpy(salt_inv, remote_rand, 16); memcpy(salt_inv + 16, my_rand, 16);
  static const uint8_t info[] = "mible-login-info";
  if (!hkdf(salt, 32, token, 12, info, sizeof(info) - 1, okm, 64)) return false;
  memcpy(kc.dev.key, okm, 16);       memcpy(kc.app.key, okm + 16, 16);
  memcpy(kc.dev.iv, okm + 32, 4);    memcpy(kc.app.iv, okm + 36, 4);
  return hmac256(kc.app.key, 16, salt, 32, info_out) &&
         hmac256(kc.dev.key, 16, salt_inv, 32, expected_remote);
}

// ---------- encrypted UART ----------
inline void crc16(const uint8_t* d, size_t n, uint8_t out[2]) {
  uint16_t s = 0;
  for (size_t i = 0; i < n; i++) s += d[i];
  s = (uint16_t)(0xFFFF - s);
  out[0] = s & 0xFF; out[1] = s >> 8;
}

// msg = plain frame without 55AA header and checksum: [len, addr, cmd, reg, payload...]
// out must hold msg_len + 16 bytes. Returns total length. rnd may be nullptr (random).
inline size_t encrypt_uart(const EncKey& k, const uint8_t* msg, size_t msg_len, uint32_t it,
                           const uint8_t* rnd, uint8_t* out) {
  uint8_t data[64], ct[68], nonce[12], r[4];
  size_t dl = msg_len - 1;
  if (dl + 4 > sizeof(data)) return 0;
  memcpy(data, msg + 1, dl);
  if (rnd) memcpy(r, rnd, 4); else MI_FILL_RANDOM(r, 4);
  memcpy(data + dl, r, 4); dl += 4;
  memcpy(nonce, k.iv, 4); memset(nonce + 4, 0, 4);
  nonce[8] = it >> 24; nonce[9] = it >> 16; nonce[10] = it >> 8; nonce[11] = it;
  if (!ccm_enc(k.key, nonce, nullptr, 0, data, dl, ct)) return 0;
  size_t cl = dl + 4, p = 0;
  out[p++] = 0x55; out[p++] = 0xAB;
  out[p++] = msg[0];
  out[p++] = it >> 24; out[p++] = it >> 16;           // first two big-endian bytes, as in the reference
  memcpy(out + p, ct, cl); p += cl;
  crc16(out + 2, p - 2, out + p); p += 2;
  return p;
}

// Returns plaintext length (= [addr, cmd, reg, payload..., rand4]) or -1.
inline int decrypt_uart(const EncKey& k, const uint8_t* msg, size_t len, uint8_t* out) {
  if (len < 5 + 4 + 2 || msg[0] != 0x55 || msg[1] != 0xAB) return -1;
  uint8_t nonce[12] = {0};
  memcpy(nonce, k.iv, 4);
  nonce[8] = msg[3]; nonce[9] = msg[4];
  size_t cl = len - 5 - 2;
  if (!ccm_dec(k.key, nonce, nullptr, 0, msg + 5, cl, out)) return -1;
  return (int)(cl - 4);
}

}  // namespace mi
