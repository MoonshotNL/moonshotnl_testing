#ifndef COMMON_H
#define COMMON_H

#define ATTR_SMIME_CERTONLY 129
#define ATTR_SMIME_REQUEST 128

typedef struct rlm_moonshot_t {
	char		*pub_key;
    char        *priv_key;
    char        *priv_key_password;
} rlm_moonshot_t;


#endif
