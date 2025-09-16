#include "eap_aka.h"

#include <stdio.h>      // printf, stb.
#include <string.h>     // memcpy, memset, strlen
#include <stddef.h>     // size_t tipus
#include <openssl/hmac.h> // HMAC-SHA1
#include <openssl/evp.h>  // SHA1 hash
#include <stdbool.h>   // bool tipus
#include <stdlib.h>    // malloc, free
#include "vowifi.h"

// --- FIPS 186-2 PRF (RFC 4187 Appendix A) ---
// RFC 4187 Appendix A: FIPS 186-2 PRF
// seed: 160b MK
// out: kert bajtok (pl. 160)
static void fips186_2_prf(const unsigned char* seed, size_t seed_len, unsigned char* out, size_t out_len) {
    unsigned char xkey[64] = {0}; // 64B puffer, elso 20B-ben az MK
    memcpy(xkey, seed, seed_len > 64 ? 64 : seed_len); // MK beirva
    unsigned int t[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}; // SHA1 IV
    size_t need = ((out_len + 39) / 40) * 40; // 40B tobbszorose
    size_t outpos = 0;
    while (outpos < need) {
        for (int wi = 0; wi < 2; wi++) { // minden iteracioban 2x20B
            // SHA1 blokk kompresszio
            unsigned int w[80];
            for (int i = 0; i < 16; i++) {
                w[i] = ((unsigned int)xkey[4*i] << 24) | ((unsigned int)xkey[4*i+1] << 16) |
                       ((unsigned int)xkey[4*i+2] << 8) | ((unsigned int)xkey[4*i+3]); // 4B-bol 32b
            }
            for (int i = 16; i < 80; i++) {
                w[i] = ((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) << 1) |
                       ((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) >> 31); // rotl32
            }
            unsigned int a = t[0], b = t[1], c = t[2], d = t[3], e = t[4];
            for (int i = 0; i < 80; i++) {
                unsigned int f, k;
                if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; } // SHA1 f1
                else if (i < 40) { f = b ^ c ^ d;            k = 0x6ED9EBA1; } // SHA1 f2
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; } // SHA1 f3
                else             { f = b ^ c ^ d;            k = 0xCA62C1D6; } // SHA1 f4
                unsigned int temp = ((a << 5) | (a >> 27)) + f + e + k + w[i]; // rotl32(a,5)
                e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
            }
            unsigned int h[5];
            h[0] = t[0] + a; h[1] = t[1] + b; h[2] = t[2] + c; h[3] = t[3] + d; h[4] = t[4] + e;
            for (int i = 0; i < 5; i++) {
                out[outpos + 4*i + wi*20]     = (h[i] >> 24) & 0xff; // 32b -> 4B
                out[outpos + 4*i + 1 + wi*20] = (h[i] >> 16) & 0xff;
                out[outpos + 4*i + 2 + wi*20] = (h[i] >> 8) & 0xff;
                out[outpos + 4*i + 3 + wi*20] = h[i] & 0xff;
            }
            // XKEY = (1 + XKEY + w_i) mod 2^160 (csak also 20B)
            unsigned char w_bytes[20];
            for (int i = 0; i < 5; i++) {
                w_bytes[4*i+0] = (h[i] >> 24) & 0xff;
                w_bytes[4*i+1] = (h[i] >> 16) & 0xff;
                w_bytes[4*i+2] = (h[i] >> 8) & 0xff;
                w_bytes[4*i+3] = h[i] & 0xff;
            }
            int carry = 1;
            for (int k = 19; k >= 0; k--) {
                carry += xkey[k] + w_bytes[k];
                xkey[k] = carry & 0xff;
                carry >>= 8;
            }
        }
        outpos += 40;
    }
}
// EAP-AKA K_aut előállítás (RFC 4187 §7, Appendix A), és AT_MAC számítás (HMAC-SHA1-128)
// Python aka1.py alapján

// Hex string to binary
// Hex string -> bináris tömb
static void hex_to_bin(const char* hex, unsigned char* out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++)
        sscanf(hex + 2*i, "%2hhx", &out[i]); // 2 karakter -> 1 bájt
}


// EAP-AKA Challenge builder (AT_RAND, AT_AUTN, AT_MAC)
// EAP-AKA Challenge üzenet felépítése (AT_RAND, AT_AUTN, AT_MAC)
static void build_eap_aka_challenge(
    const unsigned char* rand16,   // 16 bájtos RAND
    const unsigned char* autn16,   // 16 bájtos AUTN
    unsigned char* eap_out,        // kimeneti buffer
    size_t* eap_len,               // kimeneti hossz
    int identifier                 // EAP Id
) {
    unsigned char eap[128] = {0}; // EAP üzenet buffer
    size_t pos = 0;
    eap[pos++] = 0x01; // Code=1 (Request)
    eap[pos++] = identifier & 0xff; // Id
    eap[pos++] = 0x00; // Length (placeholder)
    eap[pos++] = 0x00; // Length (placeholder)
    eap[pos++] = 0x17; // Type=23 (AKA)
    eap[pos++] = 0x01; // Subtype=1 (Challenge)
    eap[pos++] = 0x00; // Reserved
    eap[pos++] = 0x00; // Reserved

    // AT_RAND (type=1)
    eap[pos++] = 0x01; // AT_RAND
    eap[pos++] = 0x05; // Length=5 (20 bytes)
    eap[pos++] = 0x00;
    eap[pos++] = 0x00;
    memcpy(eap + pos, rand16, 16); pos += 16; // RAND érték

    // AT_AUTN (type=2)
    eap[pos++] = 0x02; // AT_AUTN
    eap[pos++] = 0x05; // Length=5 (20 bytes)
    eap[pos++] = 0x00;
    eap[pos++] = 0x00;
    memcpy(eap + pos, autn16, 16); pos += 16; // AUTN érték

    // AT_MAC (type=11), 16x00
    eap[pos++] = 0x0b; // AT_MAC
    eap[pos++] = 0x05; // Length=5 (20 bytes)
    eap[pos++] = 0x00;
    eap[pos++] = 0x00;
    memset(eap + pos, 0, 16); pos += 16; // AT_MAC mező nullázva

    // Hossz kitöltése
    eap[2] = (pos >> 8) & 0xff;
    eap[3] = pos & 0xff;

    memcpy(eap_out, eap, pos); // kimeneti bufferba másolás
    *eap_len = pos; // kimeneti hossz
}

// HMAC-SHA1-128 (AT_MAC)
// AT_MAC kiszámítása: HMAC-SHA1-128 (K_aut, teljes EAP üzenet)
static void calc_at_mac(const unsigned char* k_aut, const unsigned char* eap, size_t eap_len, unsigned char* mac_out) {
    unsigned int mac_len = 0;
    HMAC(EVP_sha1(), k_aut, 16, eap, eap_len, mac_out, &mac_len); // HMAC-SHA1
    // Csak az első 16 bájt kell
}

int generateEapAkaChallenge(const char* identity, const char* randHex, const char* autnHex,
                          const char* ckHex, const char* ikHex,
                          unsigned char** out, size_t* outLen) {

    // Hex stringek binárisra alakítása
    unsigned char rand_bin[16], autn_bin[16], ck_bin[16], ik_bin[16];
    hex_to_bin(randHex, rand_bin, 16);   // RAND
    hex_to_bin(autnHex, autn_bin, 16);   // AUTN
    hex_to_bin(ckHex, ck_bin, 16);       // CK
    hex_to_bin(ikHex, ik_bin, 16);       // IK                            
    // MK = SHA1(identity || IK || CK)
    unsigned char mk[20];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL); // SHA1 init
    EVP_DigestUpdate(mdctx, identity, strlen(identity)); // Identity
    EVP_DigestUpdate(mdctx, ik_bin, 16); // IK
    EVP_DigestUpdate(mdctx, ck_bin, 16); // CK
    EVP_DigestFinal_ex(mdctx, mk, NULL); // SHA1 véglegesítés
    EVP_MD_CTX_free(mdctx);

    // RFC 4187 PRF: K_encr, K_aut, MSK, EMSK
    unsigned char prf_out[160];
    fips186_2_prf(mk, 20, prf_out, 160); // PRF
    unsigned char k_aut[16];
    memcpy(k_aut, prf_out + 16, 16); // K_aut = 16..31

    // EAP-AKA Challenge üzenet felépítése
    unsigned char eap[128];
    size_t eap_len;
    build_eap_aka_challenge(rand_bin, autn_bin, eap, &eap_len, 0x02); // identifier=0x02

    // AT_MAC kiszámítása
    unsigned char mac[20];
    calc_at_mac(k_aut, eap, eap_len, mac);

    // Eredmények kiírása
    printf("Identity: %s\n", identity);
    printf("K_aut (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", k_aut[i]);
    printf("\n");
    printf("AT_MAC (hex): ");
    for (int i = 0; i < 16; i++) printf("%02x", mac[i]);
    printf("\n");

    //EAP kiírás
    printf("eap_len: %zu\n", eap_len);
    printf("eap (hex): ");
    for (size_t i = 0; i < eap_len; i++) {
        printf("%02x", eap[i]);
    }
    printf("\n");

    //
    memcpy(eap+52, mac, 16);  // AT_MAC mező feltöltése a kiszámított MAC értékkel

        //EAP kiírás
    printf("eap_len: %zu\n", eap_len);
    printf("eap (hex): ");
    for (size_t i = 0; i < eap_len; i++) {
        printf("%02x", eap[i]);
    }
    printf("\n");

    *out = malloc(eap_len);
    if (*out == NULL) {
        return -1; // memória hiba
    }
    memcpy(*out, eap, eap_len);
    *outLen = eap_len;
    return 0;
}                            
    

/* ===================== Segédfüggvények: hex -> bytes, kiírás ===================== */
static int hexn(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static int hex_to_bytes(const char* s, uint8_t** out, size_t* out_len){
    size_t n = strlen(s);
    if(n % 2) return -1;
    size_t m = n/2;
    uint8_t* buf = (uint8_t*)malloc(m ? m : 1);
    if(!buf) return -2;
    for(size_t i=0;i<m;i++){
        int hi = hexn(s[2*i]), lo = hexn(s[2*i+1]);
        if(hi<0||lo<0){ free(buf); return -3; }
        buf[i] = (uint8_t)((hi<<4)|lo);
    }
    *out = buf; *out_len = m;
    return 0;
}
static void print_hex(const uint8_t* b, size_t n){
    for(size_t i=0;i<n;i++) printf("%02x", b[i]);
}

/* ===================== SHA-1 és HMAC-SHA1 (trunc16) ===================== */
typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t idx; } sha1_ctx;
static uint32_t rotl32(uint32_t x, uint32_t n){ return (x<<n)|(x>>(32-n)); }

static void sha1_init(sha1_ctx* c){
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE; c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->len=0; c->idx=0;
}
static void sha1_compress(uint32_t h[5], const uint8_t block[64]){
    uint32_t W[80];
    for(int i=0;i<16;i++)
        W[i] = ((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|block[4*i+3];
    for(int t=16;t<80;t++) W[t] = rotl32(W[t-3]^W[t-8]^W[t-14]^W[t-16],1);
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    for(int t=0;t<80;t++){
        uint32_t f,k;
        if(t<=19){ f=(b&c)|((~b)&d); k=0x5A827999; }
        else if(t<=39){ f=b^c^d; k=0x6ED9EBA1; }
        else if(t<=59){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else{ f=b^c^d; k=0xCA62C1D6; }
        uint32_t tmp = rotl32(a,5)+f+e+k+W[t];
        e=d; d=c; c=rotl32(b,30); b=a; a=tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
}
static void sha1_update(sha1_ctx* c, const uint8_t* p, size_t n){
    c->len += n;
    while(n--){
        c->buf[c->idx++] = *p++;
        if(c->idx==64){ sha1_compress(c->h, c->buf); c->idx=0; }
    }
}
static void sha1_final(sha1_ctx* c, uint8_t out[20]){
    uint64_t bitlen = c->len * 8;
    c->buf[c->idx++] = 0x80;
    if(c->idx>56){ while(c->idx<64) c->buf[c->idx++]=0; sha1_compress(c->h,c->buf); c->idx=0; }
    while(c->idx<56) c->buf[c->idx++]=0;
    for(int i=7;i>=0;i--) c->buf[c->idx++] = (uint8_t)((bitlen>>(8*i))&0xFF);
    sha1_compress(c->h, c->buf);
    for(int i=0;i<5;i++){
        out[4*i]  = (uint8_t)(c->h[i]>>24);
        out[4*i+1]= (uint8_t)(c->h[i]>>16);
        out[4*i+2]= (uint8_t)(c->h[i]>>8);
        out[4*i+3]= (uint8_t)(c->h[i]);
    }
}
static void hmac_sha1_trunc16(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t out16[16]){
    uint8_t k_ipad[64], k_opad[64], tk[20];
    if(key_len>64){ sha1_ctx c; sha1_init(&c); sha1_update(&c,key,key_len); sha1_final(&c,tk); key=tk; key_len=20; }
    memset(k_ipad,0,64); memset(k_opad,0,64);
    memcpy(k_ipad,key,key_len); memcpy(k_opad,key,key_len);
    for(int i=0;i<64;i++){ k_ipad[i]^=0x36; k_opad[i]^=0x5c; }
    sha1_ctx ci; sha1_init(&ci); sha1_update(&ci,k_ipad,64); sha1_update(&ci,msg,msg_len);
    uint8_t inner[20]; sha1_final(&ci,inner);
    sha1_ctx co; sha1_init(&co); sha1_update(&co,k_opad,64); sha1_update(&co,inner,20);
    uint8_t mac20[20]; sha1_final(&co,mac20);
    memcpy(out16, mac20, 16);
}

/* ===================== EAP-AKA klasszikus PRNG (FIPS 186-2 G) ===================== */
static void fips_Gt(uint8_t out20[20], const uint8_t c20[20]){
    uint32_t h[5]={0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    uint32_t W[80]={0};
    for(int i=0;i<5;i++)
        W[i] = ((uint32_t)c20[4*i]<<24)|((uint32_t)c20[4*i+1]<<16)|((uint32_t)c20[4*i+2]<<8)|c20[4*i+3];
    for(int t=16;t<80;t++) W[t]=rotl32(W[t-3]^W[t-8]^W[t-14]^W[t-16],1);
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
    for(int t=0;t<80;t++){
        uint32_t f,k;
        if(t<=19){ f=(b&c)|((~b)&d); k=0x5A827999; }
        else if(t<=39){ f=b^c^d; k=0x6ED9EBA1; }
        else if(t<=59){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
        else{ f=b^c^d; k=0xCA62C1D6; }
        uint32_t tmp = rotl32(a,5)+f+e+k+W[t];
        e=d; d=c; c=rotl32(b,30); b=a; a=tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
    for(int i=0;i<5;i++){
        out20[4*i]  = (uint8_t)(h[i]>>24);
        out20[4*i+1]= (uint8_t)(h[i]>>16);
        out20[4*i+2]= (uint8_t)(h[i]>>8);
        out20[4*i+3]= (uint8_t)(h[i]);
    }
}
static void add160_be(uint8_t a[20], const uint8_t b[20], uint32_t carry){
    for(int i=19;i>=0;i--){
        uint32_t s = (uint32_t)a[i] + b[i] + (carry & 0xFF);
        a[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
}
/* MK = SHA1( identity | IK | CK ); x0 = w0|w1; K_aut = x0[16..31] */
static void derive_k_aut(const char* identity, const uint8_t IK[16], const uint8_t CK[16], uint8_t K_aut[16]){
    sha1_ctx c; sha1_init(&c);
    sha1_update(&c, (const uint8_t*)identity, strlen(identity));
    sha1_update(&c, IK, 16);
    sha1_update(&c, CK, 16);
    uint8_t MK[20]; sha1_final(&c, MK);

    uint8_t XKEY[20]; memcpy(XKEY, MK, 20);
    uint8_t w0[20], w1[20];
    fips_Gt(w0, XKEY); add160_be(XKEY, w0, 1);
    fips_Gt(w1, XKEY); add160_be(XKEY, w1, 1);

    memcpy(K_aut,   w0+16, 4);
    memcpy(K_aut+4, w1,    12);
}

/* ===================== EAP packet MAC számítás ===================== */
static int compute_packet_mac(const uint8_t* pkt, size_t pkt_len, const uint8_t K_aut[16], uint8_t out16[16]){
    if(pkt_len < 8) return -1;
    uint8_t* m = (uint8_t*)malloc(pkt_len);
    if(!m) return -2;
    memcpy(m, pkt, pkt_len);

    /* TLV scan: AT_MAC (Type=11). Length L egység: 4 byte/word, összjelentés Type+Len+Value(+pad) */
    size_t ofs = 8;
    while(ofs + 2 <= pkt_len){
        uint8_t t = m[ofs];
        uint8_t L = m[ofs+1];
        size_t total = (size_t)L * 4;
        if(total < 4 || ofs + total > pkt_len) break;
        if(t == 11){
            for(size_t i=2;i<total;i++) m[ofs+i] = 0x00; /* value (+pad) kinullázása */
            break;
        }
        ofs += total;
    }
    hmac_sha1_trunc16(K_aut, 16, m, pkt_len, out16);
    free(m);
    return 0;
}

int verifyEapAkaResponse(struct sess_state *state) {

    bool valid = true;                            
    // Parse all hex strings to bytes /
    uint8_t *rand_b=0,*autn_b=0,*ck_b=0,*ik_b=0,*xres_b=0,*res_full_b=0,*chk_b=0,*mac_b=0,*pkt_b=0;
    size_t rand_n,autn_n,ck_n,ik_n,xres_n,res_full_n,chk_n,mac_n,pkt_n;

    // TESZT
    // MAA-ból kapottak //
    char *RAND_HEX = state->rand; //"3be67c09ce0e94c263979c61284f0205";
    char *AUTN_HEX = state->autn; //"97a0e842aa8a0001e06d3125b442a7e9";
    char *CK_HEX   = state->ck;   //"ffa8c96750a95886de3ff78b1d55abe6";
    char *IK_HEX   = state->ik;   //"c475b7976d6929e85bf26888344c9769";
    char *XRES_HEX = state->xres; //"57c56f14996876c9";

    // Identity //
     char *IDENTITY = state->identity; //"0216304037174028@nai.epc.mnc030.mcc216.3gppnetwork.org";

    // Peer által megadott értékek (attribútumok értékmezői, hex string) //
     char *RES_FULL_HEX  = state->c_res; //"004057c56f14996876c9";                 // 0x0040 + 8B RES
     char *CHECKCODE_HEX = state->c_checkcode; //"0000";                                  // 2B reserved, 0 hossz
     char *MAC_HEX       = state->c_mac;       //"000057e2b1f3c4d5e6f708192a3b4c5d6";     // 0x0012 + 16B MAC
     //char *INCOMING_EAP_PACKET_HEX = "0102003c170100000005000000011b203be67c09ce0e94c263979c61284f020500000097a0e842aa8a0001e06d3125b442a7e90b0500000057e2b1f3c4d5e6f708192a3b4c5d6"; // teljes EAP üzenet

        if (hex_to_bytes(RAND_HEX,&rand_b,&rand_n)||
        hex_to_bytes(AUTN_HEX,&autn_b,&autn_n)||
        hex_to_bytes(CK_HEX,&ck_b,&ck_n)||
        hex_to_bytes(IK_HEX,&ik_b,&ik_n)||
        hex_to_bytes(XRES_HEX,&xres_b,&xres_n)||
        hex_to_bytes(RES_FULL_HEX,&res_full_b,&res_full_n)||
        hex_to_bytes(CHECKCODE_HEX,&chk_b,&chk_n)||
        hex_to_bytes(MAC_HEX,&mac_b,&mac_n))//||
        //hex_to_bytes(INCOMING_EAP_PACKET_HEX,&pkt_b,&pkt_n))
        {
        fprintf(stderr,"Hex parse error.\n");
        valid = false;
    }

    /* Derive K_aut */
    if(ik_n!=16 || ck_n!=16){ fprintf(stderr,"IK/CK size mismatch.\n"); valid = false; }
    uint8_t K_aut[16];
    derive_k_aut(IDENTITY, ik_b, ck_b, K_aut);

    /* MAC over packet (AT_MAC value nulled) */
    uint8_t mac_calc[16];
    if(compute_packet_mac(pkt_b, pkt_n, K_aut, mac_calc)!=0){ fprintf(stderr,"MAC compute error.\n"); valid = false; }

    /* Checks */
    /* RES vs XRES */
    if(res_full_n < 2){ fprintf(stderr,"RES_FULL too short.\n"); valid = false;}
    uint16_t res_bits = (uint16_t)((res_full_b[0]<<8)|res_full_b[1]);
    size_t res_len = (res_bits + 7)/8;
    if(2+res_len > res_full_n){ fprintf(stderr,"RES_FULL length mismatch.\n"); valid = false; }
    const uint8_t* res_bytes = res_full_b + 2;
    int res_ok = (xres_n==res_len) && (memcmp(res_bytes, xres_b, res_len)==0);

    /* CHECKCODE */
    int chk_ok = (chk_n==2 && chk_b[0]==0x00 && chk_b[1]==0x00);

    /* MAC embedded vs calculated */
    if(mac_n < 2+16){ fprintf(stderr,"MAC value too short.\n"); valid = false; }
    int mac_reserved_ok = (mac_b[0]==0x00 && mac_b[1]==0x00);
    const uint8_t* mac_emb = mac_b + 2;
    int mac_ok = (memcmp(mac_calc, mac_emb, 16)==0);

    /* Output */
    printf("Incoming EAP packet (len=%zu): ", pkt_n); print_hex(pkt_b,pkt_n); printf("\n");
    printf("K_aut: "); print_hex(K_aut,16); printf("\n");

    printf("RES vs XRES: %s | RES=", res_ok?"OK":"FAIL");
    print_hex(res_bytes,res_len);
    printf(" | XRES="); print_hex(xres_b,xres_n); printf("\n");

    printf("AT_CHECKCODE reserved '0000': %s\n", chk_ok?"OK":"FAIL");

    printf("AT_MAC calc: "); print_hex(mac_calc,16);
    printf(" | embedded: "); print_hex(mac_emb,16);
    printf(" | reserved_ok: %s | match: %s\n", mac_reserved_ok?"OK":"FAIL", mac_ok?"OK":"FAIL");

    if(res_ok && chk_ok && mac_reserved_ok && mac_ok)
        printf("EAP-AKA Response: VALID\n");
    else{
        printf("EAP-AKA Response: INVALID\n");
        valid = false;
    }

    free(rand_b); free(autn_b); free(ck_b); free(ik_b); free(xres_b);
    free(res_full_b); free(chk_b); free(mac_b); free(pkt_b);
    /*
    return 0; // Csak teszteleshez                            

    bool valid = true;                            
    // Parse all hex strings to bytes /
    uint8_t *rand_b=0,*autn_b=0,*ck_b=0,*ik_b=0,*xres_b=0,*res_full_b=0,*chk_b=0,*mac_b=0,*pkt_b=0;
    size_t rand_n,autn_n,ck_n,ik_n,xres_n,res_full_n,chk_n,mac_n,pkt_n;

    // TESZT
    // MAA-ból kapottak //
    static const char *RAND_HEX = "1b203be67c09ce0e94c263979c61284f";
    static const char *AUTN_HEX = "97a0e842aa8a0001e06d3125b442a7e9";
    static const char *CK_HEX   = "ffa8c96750a95886de3ff78b1d55abe6";
    static const char *IK_HEX   = "c475b7976d6929e85bf26888344c9769";
    static const char *XRES_HEX = "57c56f14996876c9";

    // Identity //
    static const char *IDENTITY = "0216304037174028@nai.epc.mnc030.mcc216.3gppnetwork.org";

    // Peer által megadott értékek (attribútumok értékmezői, hex string) //
    static const char *RES_FULL_HEX  = "004057c56f14996876c9";                 // 0x0040 + 8B RES
    static const char *CHECKCODE_HEX = "0000";                                  // 2B reserved, 0 hossz
    static const char *MAC_HEX       = "000035a57a1221206a1fc651e8673e5c1278";  // 2B reserved + 16B MAC

    // Incoming EAP-Response/AKA-Challenge (Code..end) //
    static const char *INCOMING_EAP_PACKET_HEX =
        "0202002c17010000"
        "0303004057c56f14996876c9"
        "86010000"
        "0b05000035a57a1221206a1fc651e8673e5c1278";

    //CHECK_PARAMS(identity && ckHex && ikHex && eapResp && eapRespLen>0);    

    if (hex_to_bytes(RAND_HEX,&rand_b,&rand_n)||
        hex_to_bytes(AUTN_HEX,&autn_b,&autn_n)||
        hex_to_bytes(CK_HEX,&ck_b,&ck_n)||
        hex_to_bytes(IK_HEX,&ik_b,&ik_n)||
        hex_to_bytes(XRES_HEX,&xres_b,&xres_n)||
        hex_to_bytes(RES_FULL_HEX,&res_full_b,&res_full_n)||
        hex_to_bytes(CHECKCODE_HEX,&chk_b,&chk_n)||
        hex_to_bytes(MAC_HEX,&mac_b,&mac_n)||
        hex_to_bytes(INCOMING_EAP_PACKET_HEX,&pkt_b,&pkt_n)){
        fprintf(stderr,"Hex parse error.\n");
        valid = false;
    }

    // Derive K_aut //
    if(ik_n!=16 || ck_n!=16){ fprintf(stderr,"IK/CK size mismatch.\n"); valid = false; }
    uint8_t K_aut[16];
    derive_k_aut(IDENTITY, ik_b, ck_b, K_aut);

    // MAC over packet (AT_MAC value nulled) //
    uint8_t mac_calc[16];
    if(compute_packet_mac(pkt_b, pkt_n, K_aut, mac_calc)!=0){ fprintf(stderr,"MAC compute error.\n"); valid = false; }

    // Checks //
    // RES vs XRES //
    if(res_full_n < 2){ fprintf(stderr,"RES_FULL too short.\n"); valid = false;}
    uint16_t res_bits = (uint16_t)((res_full_b[0]<<8)|res_full_b[1]);
    size_t res_len = (res_bits + 7)/8;
    if(2+res_len > res_full_n){ fprintf(stderr,"RES_FULL length mismatch.\n"); valid = false; }
    const uint8_t* res_bytes = res_full_b + 2;
    int res_ok = (xres_n==res_len) && (memcmp(res_bytes, xres_b, res_len)==0);

    // CHECKCODE //
    int chk_ok = (chk_n==2 && chk_b[0]==0x00 && chk_b[1]==0x00);

    // MAC embedded vs calculated //
    if(mac_n < 2+16){ fprintf(stderr,"MAC value too short.\n"); valid = false; }
    int mac_reserved_ok = (mac_b[0]==0x00 && mac_b[1]==0x00);
    const uint8_t* mac_emb = mac_b + 2;
    int mac_ok = (memcmp(mac_calc, mac_emb, 16)==0);

    // Output //
    printf("Incoming EAP packet (len=%zu): ", pkt_n); print_hex(pkt_b,pkt_n); printf("\n");
    printf("K_aut: "); print_hex(K_aut,16); printf("\n");

    printf("RES vs XRES: %s | RES=", res_ok?"OK":"FAIL");
    print_hex(res_bytes,res_len);
    printf(" | XRES="); print_hex(xres_b,xres_n); printf("\n");

    printf("AT_CHECKCODE reserved '0000': %s\n", chk_ok?"OK":"FAIL");

    printf("AT_MAC calc: "); print_hex(mac_calc,16);
    printf(" | embedded: "); print_hex(mac_emb,16);
    printf(" | reserved_ok: %s | match: %s\n", mac_reserved_ok?"OK":"FAIL", mac_ok?"OK":"FAIL");

    if(res_ok && chk_ok && mac_reserved_ok && mac_ok)
        printf("EAP-AKA Response: VALID\n");
    else{
        printf("EAP-AKA Response: INVALID\n");
        valid = false;
    }

    free(rand_b); free(autn_b); free(ck_b); free(ik_b); free(xres_b);
    free(res_full_b); free(chk_b); free(mac_b); free(pkt_b);
    */
    return 0;
}

// TODO
int generateAtRandAtAutn(char **atRand, char **atAutn) {
    *atRand = strdup("1b203be67c09ce0e94c263979c61284f");
    *atAutn = strdup("97a0e842aa8a0001e06d3125b442a7e9");
    return 0;
}

