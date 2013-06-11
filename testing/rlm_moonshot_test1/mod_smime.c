#include "crypto/mod_base64.h"
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STR_MAXLEN				1024
#define MIMEHEADER_TEXT_LEN		78
#define MIMEHEADER_CERT_LEN		113

#define STATE_HEADER	0
#define STATE_BODY		1

#define MAX_MSGLEN	4096

static int mime_strip_header(int header_len, char *input, int input_len, char **output)
{
	*output = calloc(1, input_len - header_len);
	memcpy(*output, input + header_len, input_len - header_len);
	return input_len - header_len;
}

static int mime_add_header_text(char *input, int input_len, char **output)
{
	char *header = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc((sizeof(char) * input_len) + (sizeof(char) * MIMEHEADER_TEXT_LEN) + 1);
	strcpy(*output, header);
	strcat(*output, input);
	return input_len + MIMEHEADER_TEXT_LEN + 1;
}

static int mime_add_header_cert(char *input, int input_len, char **output)
{
	char *header = "Mime-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=certs-only\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc(input_len + MIMEHEADER_CERT_LEN + 1);
	strcpy(*output, header);
	strcat(*output, input);
	return input_len + MIMEHEADER_CERT_LEN + 1;
}

int pack_mime_text(char *input, int len, char **output)
{
	int out_len = 0;
	char *base64_input;
	base64_input = base64(input, len);

	out_len = mime_add_header_text(base64_input, strlen(base64_input), output);

	return out_len;
}

int unpack_mime_text(char *input, int len, char **output)
{
	char *base64_out;
	int base64_len;

	base64_len = mime_strip_header(MIMEHEADER_TEXT_LEN, input, len, &base64_out);

	*output = unbase64(base64_out, strlen(base64_out));
	return strlen(*output);
}

int pack_mime_cert(X509 *cert, char **output)
{
	BIO *bio = NULL;
	char *outbuffer;

	outbuffer = malloc(5120);
	memset(outbuffer, 0, 5120);

	bio = BIO_new_mem_buf(outbuffer, -1);
	if (!bio)
	{
		return -1;
	}

	if (!PEM_write_bio_X509(bio, cert))
	{
		BIO_free(bio);
		return -1;
	}

	mime_add_header_cert(outbuffer, strnlen(outbuffer, 5120), output);
	free(outbuffer);
	return 0;
}

int unpack_mime_cert(char *input, int len, X509 **cert)
{
	*cert = NULL;
	BIO *bio = NULL;
	char *noheader;

	mime_strip_header(MIMEHEADER_CERT_LEN, input, strlen(input), &noheader);

	bio = BIO_new_mem_buf(noheader, -1);
	if (!bio)
	{
		return -1;
	}

	PEM_read_bio_X509(bio, cert, 0, NULL);
	BIO_free(bio);
	if (!*cert)
	{
		return -1;
	}
	
	return 0;
}

char *pack_smime_text(char *input, EVP_PKEY *pkey, X509 *pubcert)
{
   STACK_OF(X509) *recips = NULL;
   CMS_ContentInfo *cms_sig = NULL, *cms_enc = NULL;
   BIO *bio_in = NULL, *bio_sig = NULL, *bio_out = NULL;
   BUF_MEM *bptr;
   char *output = NULL;
   int flags = CMS_STREAM;

   //Prepare general stuff
   OpenSSL_add_all_algorithms();

   recips = sk_X509_new_null();
   if (!recips || !sk_X509_push(recips, pubcert))
   {
      printf("recips || sk_X509_push error\n");
      exit(1);
   }

   bio_in = BIO_new_mem_buf(input, -1);
   bio_sig = BIO_new(BIO_s_mem());
   bio_out = BIO_new(BIO_s_mem());

   if (!bio_in || !bio_sig || !bio_out)
   {
      printf("bio_in || bio_sig || bio_out error\n");
      exit(1);
   }

   cms_sig = CMS_sign(pubcert, pkey, NULL, bio_in, CMS_DETACHED|CMS_STREAM);
   if (!cms_sig)
   {
      printf("cms_sig error\n");
      exit(1);
   }

   if (!SMIME_write_CMS(bio_sig, cms_sig, bio_in, CMS_DETACHED|CMS_STREAM))
   {
      printf("Error SMIME_write_CMS bio_sig");
      exit(1);
   }

   cms_enc = CMS_encrypt(recips, bio_sig, EVP_des_ede3_cbc(), flags);

   if (!cms_enc)
   {
      printf("cms error\n");
      exit(1);
   }

   if (!SMIME_write_CMS(bio_out, cms_enc, bio_sig, flags))
   {
      printf("SMIME write error\n");
      exit(1);
   }

   BIO_get_mem_ptr(bio_out, &bptr);
   output = bptr->data;
   output = strndup(bptr->data, bptr->length);

   CMS_ContentInfo_free(cms_sig);
   CMS_ContentInfo_free(cms_enc);
   BIO_free(bio_in);
   BIO_free(bio_sig);
   BIO_free(bio_out);

   return output;
}

char *unpack_smime_text(char *input, EVP_PKEY *pkey, X509 *cert)
{
	BIO *bio_in = NULL, *bio_out = NULL;
	CMS_ContentInfo *cms = NULL;
	char *output = NULL;
	BUF_MEM *bptr = NULL;

	OpenSSL_add_all_algorithms();

	bio_in = BIO_new_mem_buf(input, -1);
	bio_out = BIO_new(BIO_s_mem());

	if (!bio_in || !bio_out)
	{
		printf("dectext: error creating bio_in, bio_dec or bio_out\n");
		exit(1);
	}
	
	cms = SMIME_read_CMS(bio_in, NULL);
	if (!cms)
	{
		printf("Error parsing message to CMS\n");
		exit(1);
	}

	if (!CMS_decrypt(cms, pkey, cert, NULL, bio_out, 0))
	{
		printf("Error decrypting message\n");
		exit(1);
	}

	BIO_get_mem_ptr(bio_out, &bptr);
	output = strndup(bptr->data, bptr->length);

	CMS_ContentInfo_free(cms);
   BIO_free(bio_in);
   BIO_free(bio_out);

	return output;
}
