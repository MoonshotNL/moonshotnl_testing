#ifndef MOD_SMIME_H
#define MOD_SMIME_H

#include <openssl/x509.h>

extern int pack_mime_text(char *input, int len, char **output);
extern int unpack_mime_text(char *input, int len, char **output);

extern int pack_mime_cert(X509 *input, char **output);
extern void unpack_mime_cert(char *input, int len, X509 **output);

extern char *pack_smime_text(char *input, EVP_PKEY *pkey, X509 *pubcert);
extern char *unpack_smime_text(char *input, EVP_PKEY *pkey, X509 *cert);

#endif
