#ifndef ntruplus_set_ctx_params_list
static const OSSL_PARAM ntruplus_set_ctx_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
    OSSL_PARAM_END
};
#endif

#ifndef ntruplus_set_ctx_params_st
struct ntruplus_set_ctx_params_st {
    OSSL_PARAM *ikme;
};
#endif

#ifndef ntruplus_set_ctx_params_decoder
static int ntruplus_set_ctx_params_decoder
    (const OSSL_PARAM *p, struct ntruplus_set_ctx_params_st *r)
{
    const char *s;

    memset(r, 0, sizeof(*r));
    if (p != NULL)
        for (; (s = p->key) != NULL; p++)
            if (ossl_likely(strcmp("ikme", s + 0) == 0)) {
                /* OSSL_KEM_PARAM_IKME */
                if (ossl_unlikely(r->ikme != NULL)) {
                    ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER,
                                   "param %s is repeated", s);
                    return 0;
                }
                r->ikme = (OSSL_PARAM *)p;
            }
    return 1;
}
#endif
/* End of machine generated */
