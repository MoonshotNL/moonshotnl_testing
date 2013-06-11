#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include <openssl/x509.h>

#include "common.h"
#include "mod_smime.h"

#define STR_MAXLEN					1024

#define STATE_TIMESTAMP				0
#define STATE_PROXYDN				1
#define STATE_SERVICEDN				2
#define STATE_REQUIRED_ATTR_LEN		3
#define STATE_REQUIRED_ATTR			4
#define STATE_REQUESTED_ATTR_LEN	5
#define STATE_REQUESTED_ATTR		6

extern EVP_PKEY *private_key;

typedef struct avp_struct
{
	char *attribute;
	char *value;
} AVP;

typedef struct attr_req_in
{
	unsigned long timestamp;
	char *proxydn;
	char *servicedn;
	int required_attr_len;
	char **required_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_IN;

typedef struct attr_req_out
{
	unsigned long timestamp;
	char *servicedn;
	int provided_attr_len;
	AVP *provided_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_OUT;

static ATTR_REQ_IN *parse_attr_req(char *input, int len)
{
   ATTR_REQ_IN *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ_IN));
   int input_cur = 0;

   char item_tmp[STR_MAXLEN];
   int item_cur = 0;

   int attr_p = 0;

   int state = STATE_TIMESTAMP;

   while(input_cur <= len)
   {
      switch (state)
      {
         case STATE_TIMESTAMP:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';
               tmp_attr_req->timestamp = strtol(item_tmp, NULL, 10);
               state++;
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_PROXYDN:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';
               tmp_attr_req->proxydn = rad_malloc(sizeof(char) * (item_cur + 1));
               memcpy(tmp_attr_req->proxydn, item_tmp, sizeof(char) * (item_cur + 1));
               state++;
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_SERVICEDN:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';
               tmp_attr_req->servicedn = rad_malloc(sizeof(char) * (item_cur + 1));
               memcpy(tmp_attr_req->servicedn, item_tmp, sizeof(char) * (item_cur + 1));
               state++;
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_REQUIRED_ATTR_LEN:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';
               tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10);

               if (tmp_attr_req->required_attr_len == 0)
               {
                  state += 2;
               }
               else
               {
                  state++;
               }

               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_REQUIRED_ATTR:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';

               if (attr_p == 0)
               {
                  tmp_attr_req->required_attr = rad_malloc(sizeof(char *));
                  tmp_attr_req->required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
               }
               else
               {
                  tmp_attr_req->required_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
                  tmp_attr_req->required_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
               }

               memcpy(tmp_attr_req->required_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
               attr_p++;

               if (attr_p >= tmp_attr_req->required_attr_len)
               {
                  state++;
                  attr_p = 0;
               }
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_REQUESTED_ATTR_LEN:
            if (input[input_cur] == ':')
            {
               item_tmp[item_cur] = '\0';
               tmp_attr_req->requested_attr_len = (int) strtol(item_tmp, NULL, 10);

               if (tmp_attr_req->required_attr_len == 0)
               {
                  state += 2;
               }
               else
               {
                  state++;
               }

               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
         case STATE_REQUESTED_ATTR:
            if (input_cur == len)
            {
               item_tmp[item_cur] = '\0';

               if (attr_p == 0)
               {
                  tmp_attr_req->requested_attr = rad_malloc(sizeof(char *));
                  tmp_attr_req->requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
               }
               else
               {
                  tmp_attr_req->requested_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
                  tmp_attr_req->requested_attr[attr_p] = rad_malloc(sizeof(char) * (item_cur + 1));
               }


               memcpy(tmp_attr_req->requested_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
               attr_p++;

               if (attr_p >= tmp_attr_req->requested_attr_len)
               {
                  state++;
                  attr_p = 0;
               }
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;
               break;
            }
            item_tmp[item_cur] = input[input_cur];
            item_cur++;
            input_cur++;
            break;
      }
   }
   return tmp_attr_req;
}

static AVP *get_avps_by_attributes(char **attributes, int length)
{
   //This function is to be implemented for the IDPs auathentication backend
   AVP *avp_list;
   int i;
   char *dummy_attribute = "DummyAttr";
   char *dummy_value = "DummyVal";

   avp_list = rad_malloc(sizeof(AVP) * length);
   if (!avp_list)
   {
      return NULL;
   }

   for (i = 0; i < length; i++)
   {
      avp_list[i].attribute = strdup(dummy_attribute);
      if (!avp_list[i].attribute)
         return NULL;

      avp_list[i].value = strdup(dummy_value);
      if (!avp_list[i].value)
         return NULL;
   }

   return avp_list;
}

static ATTR_REQ_OUT *get_attr_req_out(ATTR_REQ_IN *input)
{
   ATTR_REQ_OUT *outstruct;
   AVP *pairs;

   outstruct = rad_malloc(sizeof(ATTR_REQ_OUT));
   memset(outstruct, 0, sizeof(ATTR_REQ_OUT));

   pairs = get_avps_by_attributes(input->required_attr, input->required_attr_len);
   if (!pairs)
   {
      return NULL;
   }

   outstruct->servicedn = input->servicedn;
   outstruct->provided_attr_len = input->required_attr_len;
   outstruct->provided_attr = pairs;
   outstruct->requested_attr_len = input->requested_attr_len;
   outstruct->requested_attr = input->requested_attr;
   outstruct->timestamp = (unsigned long) time(0);

   return outstruct;
}

static int attr_req_out_to_string(ATTR_REQ_OUT *input, char **output)
{
   char buffer[STR_MAXLEN];
   int i;

   memset(buffer, 0, STR_MAXLEN);

   sprintf(buffer, "%ld:%s:%i:", input->timestamp, input->servicedn, input->provided_attr_len);
   for (i = 0; i < input->provided_attr_len; i++)
   {
      sprintf(buffer + strlen(buffer), "%s=%s:", input->provided_attr[i].attribute, input->provided_attr[i].value);
   }
   sprintf(buffer + strlen(buffer), "%i:", input->requested_attr_len);
   for (i = 0; i < input->requested_attr_len; i++)
   {
      if (i == input->requested_attr_len - 1)
         sprintf(buffer + strlen(buffer), "%s", input->requested_attr[i]);
      else
         sprintf(buffer + strlen(buffer), "%s:", input->requested_attr[i]);
   }

   *output = rad_malloc(strlen(buffer));
   strcpy(*output, buffer);
   return strlen(*output);
}

static X509 *get_matching_certificate(REQUEST *request, char *dn)
{
	X509 *tmp_cert;

	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_MOONSHOT_CERTIFICATE)
		{
			unpack_mime_cert((char *)vp->data.octets, vp->length, &tmp_cert);
			
			if (strcmp(tmp_cert->name, dn) == 0)
			{
				return tmp_cert;
			}
			free(tmp_cert);
		}
	} while ((vp = vp->next) != 0);
	return NULL;
}

static void handle_request(REQUEST *request, VALUE_PAIR *vp)
{
	char *input_data;
	int input_len;
	char *output_data;
	int output_len;
	char *smime_msg;
	ATTR_REQ_OUT *outstruct;
	
	input_len = unpack_mime_text((char *)vp->data.octets, vp->length, &input_data);
	ATTR_REQ_IN *attr_request = parse_attr_req(input_data, input_len);
	if (!attr_request)
	{
		return;
	}

	X509 *cert = get_matching_certificate(request, attr_request->proxydn);
	if (!cert)
	{
		return;
	}

	outstruct = get_attr_req_out(attr_request);
	output_len = attr_req_out_to_string(outstruct, &output_data);
	smime_msg = pack_smime_text(output_data, private_key, cert);
	VALUE_PAIR *avp_smime = pairmake("Moonshot-Request",smime_msg, T_OP_EQ);
	pairadd(&request->reply->vps, avp_smime);
	return;
}

void idp_handle_requests(REQUEST *request)
{
	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_MOONSHOT_REQUEST)
		{
			handle_request(request, vp);
		}
	} while ((vp = vp->next) != 0);
}
