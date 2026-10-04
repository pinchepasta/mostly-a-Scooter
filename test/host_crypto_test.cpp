// Host-side check of src/mi_crypto.h against the reference test vectors.
// Build/run (needs libmbedtls-dev):  g++ -std=c++17 -o t host_crypto_test.cpp -lmbedcrypto && ./t
#include <stdlib.h>
#include <stdio.h>
#define MI_FILL_RANDOM(b,n) do{ for(size_t _i=0;_i<(n);_i++) (b)[_i]=rand(); }while(0)
#include "../src/mi_crypto.h"
static void hex(const char*s,uint8_t*o,size_t n){for(size_t i=0;i<n;i++){unsigned v;sscanf(s+2*i,"%2x",&v);o[i]=v;}}
static void pr(const char*l,const uint8_t*d,size_t n){printf("%s=",l);for(size_t i=0;i<n;i++)printf("%02x",d[i]);printf("\n");}
int main(){
  int fail=0;
  // crc16
  uint8_t b[9]={0xa1,0x21,0xf3,4,5,6,7,8,9},c[2]; mi::crc16(b,9,c);
  printf("crc16 %s\n",(c[0]==0x23&&c[1]==0xfe)?"OK":"FAIL"); fail|=!(c[0]==0x23&&c[1]==0xfe);
  // encrypt vector
  mi::EncKey k; hex("5066d82368375a1f6a0a3eba1317b525",k.key,16); hex("28cee53e",k.iv,4);
  uint8_t rnd[4],cmd[5],exp[19],out[64]; hex("897045e7",rnd,4); hex("032001100e",cmd,5);
  hex("55ab03000016b2eddb0b680532a988c4f2dbf9",exp,19);
  size_t n=mi::encrypt_uart(k,cmd,5,0,rnd,out);
  bool ok=(n==19&&!memcmp(out,exp,19)); printf("encrypt_uart %s\n",ok?"OK":"FAIL"); if(!ok)pr("got",out,n); fail|=!ok;
  // decrypt vector
  mi::EncKey k2; hex("462f3fcc74200ca5f77ee2a581c42af0",k2.key,16); hex("f8901a05",k2.iv,4);
  uint8_t enc[32],dec[64]; hex("55ab1001009a70888f3a27d8378bb07f7d8ce4cce88ab54a50595ad6c019c7f2",enc,32);
  int dl=mi::decrypt_uart(k2,enc,32,dec);
  char txt[32]={0}; if(dl>=7){memcpy(txt,dec+3,dl-3-4);}
  ok=(dl>0&&!strcmp(txt,"26354/00467353")); printf("decrypt_uart %s (%s)\n",ok?"OK":"FAIL",txt); fail|=!ok;
  // round trip
  uint8_t rt[64],pl[64]; size_t rn=mi::encrypt_uart(k,cmd,5,0,nullptr,rt);
  int rl=mi::decrypt_uart(k,rt,rn,pl); ok=(rl==8&&!memcmp(pl,cmd+1,4)); printf("roundtrip %s\n",ok?"OK":"FAIL"); fail|=!ok;
  // ECDH agreement + did sizes
  mi::KeyPair a,bk; uint8_t pa[64],pb[64],s1[32],s2[32];
  mi::gen_keypair(a,pa); mi::gen_keypair(bk,pb);
  mi::shared_secret(a,pb,s1); mi::shared_secret(bk,pa,s2);
  ok=!memcmp(s1,s2,32); printf("ecdh agree %s\n",ok?"OK":"FAIL"); fail|=!ok;
  uint8_t ri[24]={1,0,0,0,0,0x62,0x6c,0x74,0x2e,0x33,0x2e,0x31,0x36,0x33,0x39,0x34,0x74,0x33,0x67,0x34,0x6c,0x63,0x30,0x30};
  uint8_t did[64],tok[12]; size_t dlen=0;
  ok=mi::calc_did(a,pb,ri,24,did,&dlen,tok)&&dlen==24; printf("calc_did len=%zu %s\n",dlen,ok?"OK":"FAIL"); fail|=!ok;
  // HKDF cross-check inputs (fixed)
  uint8_t ikm[32],okm[64]; for(int i=0;i<32;i++)ikm[i]=i;
  mi::hkdf(nullptr,0,ikm,32,(const uint8_t*)"mible-setup-info",16,okm,64); pr("hkdf_setup",okm,64);
  uint8_t salt[32],tkn[12]; for(int i=0;i<32;i++)salt[i]=0xA0+i; for(int i=0;i<12;i++)tkn[i]=i*3;
  mi::hkdf(salt,32,tkn,12,(const uint8_t*)"mible-login-info",16,okm,64); pr("hkdf_login",okm,64);
  // login symmetry: scooter side computes with roles swapped
  uint8_t mr[16],rr[16]; for(int i=0;i<16;i++){mr[i]=i;rr[i]=0x40+i;}
  uint8_t info[32],expct[32]; mi::Keychain kc; mi::calc_login(mr,rr,tkn,info,expct,kc);
  pr("login_info",info,32); pr("login_expected",expct,32);
  return fail;
}
