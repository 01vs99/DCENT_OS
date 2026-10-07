/* SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
 * SPDX-License-Identifier: GPL-3.0-only
 * Independent freestanding SHA-256 implementation for the bounded RAM entry.
 */
#ifndef DCENT_CLASSIC_SHA256_H
#define DCENT_CLASSIC_SHA256_H
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
struct sha256_state { u32 words[8]; u64 bytes; u32 used; u8 block[64]; };
static u32 rotr(u32 value, u32 count) { return (value >> count) | (value << (32 - count)); }
static const u32 sha256_rounds[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static void sha256_compress(struct sha256_state *s) {
  u32 w[64], a=s->words[0], b=s->words[1], c=s->words[2], d=s->words[3];
  u32 e=s->words[4], f=s->words[5], g=s->words[6], h=s->words[7];
  for (u32 i=0; i<16; ++i) {
    const u8 *p=s->block+i*4;
    w[i]=((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];
  }
  for (u32 i=16; i<64; ++i) {
    u32 x=w[i-15], y=w[i-2];
    w[i]=w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>10));
  }
  for (u32 i=0; i<64; ++i) {
    u32 first=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+sha256_rounds[i]+w[i];
    u32 second=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
    h=g; g=f; f=e; e=d+first; d=c; c=b; b=a; a=first+second;
  }
  s->words[0]+=a; s->words[1]+=b; s->words[2]+=c; s->words[3]+=d;
  s->words[4]+=e; s->words[5]+=f; s->words[6]+=g; s->words[7]+=h;
}
static void sha256_init(struct sha256_state *s) {
  static const u32 initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  for (u32 i=0; i<8; ++i) s->words[i]=initial[i];
  s->bytes=0; s->used=0;
}
static void sha256_update(struct sha256_state *s, const u8 *data, u64 size) {
  s->bytes+=size;
  while (size) {
    u32 take=(size<64-s->used)?(u32)size:64-s->used;
    for (u32 i=0; i<take; ++i) s->block[s->used+i]=data[i];
    s->used+=take; data+=take; size-=take;
    if (s->used==64) { sha256_compress(s); s->used=0; }
  }
}
static void sha256_final(struct sha256_state *s, u8 out[32]) {
  u64 bits=s->bytes*8;
  s->block[s->used++]=0x80;
  if (s->used>56) {
    while (s->used<64) s->block[s->used++]=0;
    sha256_compress(s); s->used=0;
  }
  while (s->used<56) s->block[s->used++]=0;
  for (u32 i=0; i<8; ++i) s->block[63-i]=(u8)(bits>>(i*8));
  sha256_compress(s);
  for (u32 i=0; i<32; ++i) out[i]=(u8)(s->words[i/4]>>(24-(i%4)*8));
}
static void sha256(const u8 *data, u64 size, u8 out[32]) {
  struct sha256_state state;
  sha256_init(&state); sha256_update(&state,data,size); sha256_final(&state,out);
}
#endif
