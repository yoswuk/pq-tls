/* Thread-local SHAKE bridge used by parameterized NTRU+ code. */
#include <openssl/crypto.h>
#include "ntruplus_hash.h"
#include "ntruplus_local.h"

#if defined(_MSC_VER)
# define NTRUPLUS_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
# define NTRUPLUS_THREAD_LOCAL __thread
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
# define NTRUPLUS_THREAD_LOCAL _Thread_local
#else
# error "NTRU+ SHAKE bridge requires thread-local storage"
#endif

static NTRUPLUS_THREAD_LOCAL const struct ntruplus_key_st *ntruplus_current_key;
static NTRUPLUS_THREAD_LOCAL EVP_MD_CTX *ntruplus_current_shake_ctx;
static NTRUPLUS_THREAD_LOCAL int ntruplus_current_shake_failed;

# undef NTRUPLUS_THREAD_LOCAL

static void ntruplus_push_shake_state(const struct ntruplus_key_st *key,
                                      NTRUPLUS_SHAKE_STATE *state)
{
    state->key = key;
    state->prev_key = ntruplus_current_key;
    state->prev_ctx = ntruplus_current_shake_ctx;
    state->prev_failed = ntruplus_current_shake_failed;
    ntruplus_current_key = state->key;
    ntruplus_current_shake_ctx = state->shake_ctx;
    ntruplus_current_shake_failed = 0;
}

static void ntruplus_pop_shake_state(const NTRUPLUS_SHAKE_STATE *state)
{
    ntruplus_current_key = state->prev_key;
    ntruplus_current_shake_ctx = state->prev_ctx;
    ntruplus_current_shake_failed = state->prev_failed;
}

static void ntruplus_mark_shake_failed(uint8_t *out, size_t outlen)
{
    ntruplus_current_shake_failed = 1;
    if (out != NULL)
        OPENSSL_cleanse(out, outlen);
}

static void ntruplus_shake256_update(uint8_t *out, size_t outlen,
                                     const uint8_t *prefix,
                                     size_t prefix_len,
                                     const uint8_t *in, size_t inlen)
{
    EVP_MD_CTX *ctx = ntruplus_current_shake_ctx;

    if (out == NULL
        || (prefix_len != 0 && prefix == NULL)
        || (inlen != 0 && in == NULL)
        || ntruplus_current_key == NULL
        || ctx == NULL
        || ntruplus_current_key->shake256_md == NULL) {
        ntruplus_mark_shake_failed(out, outlen);
        return;
    }

    if (!EVP_MD_CTX_reset(ctx)
        || !EVP_DigestInit_ex2(ctx, ntruplus_current_key->shake256_md, NULL)
        || (prefix_len != 0 && !EVP_DigestUpdate(ctx, prefix, prefix_len))
        || (inlen != 0 && !EVP_DigestUpdate(ctx, in, inlen))
        || !EVP_DigestFinalXOF(ctx, out, outlen))
        ntruplus_mark_shake_failed(out, outlen);
}

void ntruplus_shake256(uint8_t *out, size_t outlen,
                       const uint8_t *in, size_t inlen)
{
    ntruplus_shake256_update(out, outlen, NULL, 0, in, inlen);
}

void ntruplus_shake256_prefix(uint8_t *out, size_t outlen,
                              uint8_t prefix,
                              const uint8_t *in, size_t inlen)
{
    ntruplus_shake256_update(out, outlen, &prefix, 1, in, inlen);
}

int ntruplus_begin_shake(const struct ntruplus_key_st *key,
                         EVP_MD_CTX *caller_ctx,
                         NTRUPLUS_SHAKE_STATE *state)
{
    if (state == NULL || key == NULL || key->shake256_md == NULL)
        return 0;

    state->shake_ctx = caller_ctx;
    state->owns_shake_ctx = 0;
    if (state->shake_ctx == NULL) {
        state->shake_ctx = EVP_MD_CTX_new();
        if (state->shake_ctx == NULL)
            return 0;
        state->owns_shake_ctx = 1;
    }

    ntruplus_push_shake_state(key, state);
    return 1;
}

int ntruplus_end_shake(NTRUPLUS_SHAKE_STATE *state)
{
    int ret;

    if (state == NULL)
        return 0;
    ret = ntruplus_current_key == state->key
        && ntruplus_current_shake_ctx == state->shake_ctx
        && !ntruplus_current_shake_failed;

    ntruplus_pop_shake_state(state);
    if (state->shake_ctx != NULL)
        EVP_MD_CTX_reset(state->shake_ctx);
    if (state->owns_shake_ctx)
        EVP_MD_CTX_free(state->shake_ctx);
    OPENSSL_cleanse(state, sizeof(*state));
    return ret;
}
