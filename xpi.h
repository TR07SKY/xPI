#ifndef XPI_H
#define XPI_H

#include "utils/uint256.h"
#include "utils/xpimath.h"

#include "crypto/sph_sha2.h"
#include "crypto/sph_keccak.h" //sha3
#include "crypto/sph_haval.h"
#include "crypto/sph_whirlpool.h"
#include "crypto/sph_ripemd.h"
#include "crypto/blake2b.h"
#include "crypto/poly1305.h"

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_sha256_context     z_sha256;
GLOBAL sph_sha512_context     z_sha512;
GLOBAL sph_keccak512_context  z_keccak;
GLOBAL sph_whirlpool_context  z_whirlpool;
GLOBAL sph_haval256_5_context z_haval;
GLOBAL sph_ripemd160_context  z_ripemd;
GLOBAL blake2b_context        z_blake2b;
GLOBAL poly1305_context       z_poly1305;

#define fillz() do { \
    sph_sha512_init(&z_sha512); \
    sph_sha256_init(&z_sha256); \
    sph_keccak512_init(&z_keccak); \
    sph_whirlpool_init(&z_whirlpool); \
    sph_haval256_5_init(&z_haval); \
    sph_ripemd160_init(&z_ripemd); \
    blake2b_init(&z_blake2b); \
    poly1305_init(&z_poly1305); \
} while (0)

#define ZSHA256 (memcpy(&ctx_sha256, &z_sha256, sizeof(z_sha256)))
#define ZSHA512 (memcpy(&ctx_sha512, &z_sha512, sizeof(z_sha512)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))
#define ZHAVAL (memcpy(&ctx_haval, &z_haval, sizeof(z_haval)))
#define ZRIPEMD (memcpy(&ctx_ripemd, &z_ripemd, sizeof(z_ripemd)))
#define ZBLAKE2B (memcpy(&ctx_blake2b, &z_blake2b, sizeof(z_blake2b)))
#define ZPOLY1305 (memcpy(&ctx_poly1305, &z_poly1305, sizeof(z_poly1305)))

#define BITS_PER_DIGIT 3.32192809488736234787
#define EPS (std::numeric_limits<double>::epsilon())

#define NM7M 5
#define SW_DIVS 5

template<typename T1>
inline uint256 hash_M7M_v2(const T1 pbegin, const T1 pend, const unsigned int nnNonce)
{
    sph_sha256_context       ctx_sha256;
    sph_sha512_context       ctx_sha512;
    sph_keccak512_context    ctx_keccak;
    sph_whirlpool_context    ctx_whirlpool;
    sph_haval256_5_context   ctx_haval;
    sph_ripemd160_context    ctx_ripemd;
    blake2b_context          ctx_blake2b;
    poly1305_context         ctx_poly1305;

    static unsigned char pblank[1];
    int bytes, nnNonce2 = (int)(nnNonce / 2);

    uint512 hash[7];
    uint256 finalhash;
    for(int i = 0 ; i < 7 ; i++)
        hash[i] = 0;

    const void* ptr = (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0]));
    size_t sz = (pend - pbegin) * sizeof(pbegin[0]);

    blake2b_init(&ctx_blake2b);
    // ZBLAKE2B;
    blake2b(&ctx_blake2b, ptr, sz);
    blake2b_close(&ctx_blake2b, static_cast<void*>(&hash[0]));

    sph_sha512_init(&ctx_sha512);
    // ZSHA512;
    sph_sha512 (&ctx_sha512, ptr, sz);
    sph_sha512_close(&ctx_sha512, static_cast<void*>(&hash[1]));

    sph_keccak512_init(&ctx_keccak);
    // ZKECCAK;
    sph_keccak512 (&ctx_keccak, ptr, sz);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[2]));

    sph_whirlpool_init(&ctx_whirlpool);
    // ZWHIRLPOOL;
    sph_whirlpool (&ctx_whirlpool, ptr, sz);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[3]));

    sph_haval256_5_init(&ctx_haval);
    // ZHAVAL;
    sph_haval256_5 (&ctx_haval, ptr, sz);
    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[4]));

    poly1305_init(&ctx_poly1305);
    // ZPOLY1305;
    poly1305 (&ctx_poly1305, (const unsigned char*)ptr, sz);
    char str_poly1305[33];
    poly1305_close(&ctx_poly1305, str_poly1305); hash[5].SetHex(str_poly1305);

    sph_ripemd160_init(&ctx_ripemd);
    // ZRIPEMD;
    sph_ripemd160 (&ctx_ripemd, ptr, sz);
    sph_ripemd160_close(&ctx_ripemd, static_cast<void*>(&hash[6]));

    //printf("%s\n", hash[6].GetHex().c_str());

    mpz_t bns[8];
    //Take care of zeros and load gmp
    for(int i = 0 ; i < 7 ; i++)
    {
        if(hash[i] == 0)
            hash[i] = 1;

        mpz_init(bns[i]);
        mpz_set_uint512(bns[i], hash[i]);
    }

    mpz_init(bns[7]);
    mpz_set_ui(bns[7], 0);
    for(int i = 0 ; i < 7 ; i++)
        mpz_add(bns[7], bns[7], bns[i]);

    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product, 1);

    //mpz_pow_ui(bns[7], bns[7], 2);
    for(int i = 0 ; i < 8 ; i++)
        mpz_mul(product, product, bns[i]);

    mpz_pow_ui(product, product, 2);

    bytes = mpz_sizeinbase(product, 256);
    //printf("M7M data space: %iB\n", bytes);
    char *data = (char*)malloc(bytes);
    mpz_export(data, NULL, -1, 1, 0, 0, product);

    sph_sha256_init(&ctx_sha256);
    //ZSHA256;
    sph_sha256 (&ctx_sha256, data, bytes);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&finalhash));
    //printf("finalhash = %s\n", hash[6].GetHex().c_str());
    free(data);

    int digits = (int)((sqrt((double)(nnNonce2)) * (1. + EPS)) / 9000 + 75);
    //int iterations=(int)((sqrt((double)(nnNonce2))+EPS)/500+350); // <= 500
    //int digits=100;
    int iterations = 20; // <= 500
    mpf_set_default_prec((long int)(digits * BITS_PER_DIGIT + 16));

    mpz_t magipi;
    mpz_t magisw;
    mpf_t magifpi;
    mpf_t mpa1, mpb1, mpt1, mpp1;
    mpf_t mpa2, mpb2, mpt2, mpp2;
    mpf_t mpsft;

    mpz_init(magipi);
    mpz_init(magisw);
    mpf_init(magifpi);
    mpf_init(mpsft);
    mpf_init(mpa1);
    mpf_init(mpb1);
    mpf_init(mpt1);
    mpf_init(mpp1);

    mpf_init(mpa2);
    mpf_init(mpb2);
    mpf_init(mpt2);
    mpf_init(mpp2);

    uint32_t usw_;
    usw_ = sw_(nnNonce2, SW_DIVS);
    if (usw_ < 1) usw_ = 1;
        mpz_set_ui(magisw, usw_);

    uint32_t mpzscale = mpz_size(magisw);
    for(int i = 0 ; i < NM7M ; i++)
    {
        if (mpzscale > 1000)
            mpzscale = 1000;
        else if (mpzscale < 1)
            mpzscale = 1;

        //if(fDebugMagi) printf("mpzscale: %d\n", mpzscale);

        mpf_set_ui(mpa1, 1);
        mpf_set_ui(mpb1, 2);
        mpf_set_d(mpt1, 0.25 * mpzscale);
        mpf_set_ui(mpp1, 1);
        mpf_sqrt(mpb1, mpb1);
        mpf_ui_div(mpb1, 1, mpb1);
        mpf_set_ui(mpsft, 10);

        for(int i = 0 ; i <= iterations ; i++)
        {
            mpf_add(mpa2, mpa1, mpb1);
            mpf_div_ui(mpa2, mpa2, 2);
            mpf_mul(mpb2, mpa1, mpb1);
            mpf_abs(mpb2, mpb2);
            mpf_sqrt(mpb2, mpb2);
            mpf_sub(mpt2, mpa1, mpa2);
            mpf_abs(mpt2, mpt2);
            mpf_sqrt(mpt2, mpt2);
            mpf_mul(mpt2, mpt2, mpp1);
            mpf_sub(mpt2, mpt1, mpt2);
            mpf_mul_ui(mpp2, mpp1, 2);
            mpf_swap(mpa1, mpa2);
            mpf_swap(mpb1, mpb2);
            mpf_swap(mpt1, mpt2);
            mpf_swap(mpp1, mpp2);
        }

        mpf_add(magifpi, mpa1, mpb1);
        mpf_pow_ui(magifpi, magifpi, 2);
        mpf_div_ui(magifpi, magifpi, 4);
        mpf_abs(mpt1, mpt1);
        mpf_div(magifpi, magifpi, mpt1);

        //mpf_out_str(stdout, 10, digits+2, magifpi);

        mpf_pow_ui(mpsft, mpsft, digits / 2);
        mpf_mul(magifpi, magifpi, mpsft);

        mpz_set_f(magipi, magifpi);

        //mpz_set_ui(magipi,1);

        mpz_add(product,product,magipi);
        mpz_add(product,product,magisw);

        if(finalhash == 0) finalhash = 1;
            mpz_set_uint256(bns[0], finalhash);

        mpz_add(bns[7], bns[7], bns[0]);

        mpz_mul(product, product, bns[7]);
        mpz_cdiv_q (product, product, bns[0]);
        if (mpz_sgn(product) <= 0)
            mpz_set_ui(product, 1);

        bytes = mpz_sizeinbase(product, 256);
        mpzscale = bytes;
        //printf("M7M data space: %iB\n", bytes);
        char *bdata = (char*)malloc(bytes);
        mpz_export(bdata, NULL, -1, 1, 0, 0, product);

        sph_sha256_init(&ctx_sha256);
        // ZSHA256;
        sph_sha256 (&ctx_sha256, bdata, bytes);
        sph_sha256_close(&ctx_sha256, static_cast<void*>(&finalhash));
        free(bdata);
        //    printf("finalhash = %s\n", finalhash.GetHex().c_str());
    }
    //Free the memory
    for(int i = 0 ; i < 8 ; i++)
        mpz_clear(bns[i]);

    //mpz_clear(dSpectralWeight);
    mpz_clear(product);

    mpz_clear(magipi);
    mpz_clear(magisw);
    mpf_clear(magifpi);
    mpf_clear(mpsft);
    mpf_clear(mpa1);
    mpf_clear(mpb1);
    mpf_clear(mpt1);
    mpf_clear(mpp1);

    mpf_clear(mpa2);
    mpf_clear(mpb2);
    mpf_clear(mpt2);
    mpf_clear(mpp2);

    return finalhash;
}

#endif // XPI_H
