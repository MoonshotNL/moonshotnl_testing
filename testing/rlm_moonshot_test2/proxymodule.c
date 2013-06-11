#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_smime.h"

#define STR_MAXLEN					1024

#define STATE_TIMESTAMP				0
#define STATE_SERVICEDN				1
#define STATE_PROVIDED_ATTR_LEN		2
#define STATE_PROVIDED_ATTR			3
#define STATE_REQUESTED_ATTR_LEN	4
#define STATE_REQUESTED_ATTR		5
#define STATE_LIM					5

typedef struct avp_struct
{
	char *attribute;
	char *value;
} AVP;

typedef struct attr_req_in
{
	unsigned long timestamp;
	char *servicedn;
	int provided_attr_len;
	AVP *provided_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_IN;

typedef struct attr_req_out
{
	unsigned long timestamp;
	char *servicedn;
	int requested_attr_len;
	AVP *requested_attr;
} ATTR_REQ_OUT;

AVP *atoavp(char *input)
{
	AVP *tmp_avp;
	int sep_offset = 0;
	
	while (sep_offset < strlen(input) && input[sep_offset] != '=')
		sep_offset++;
	
	if (sep_offset == strlen(input) - 1)
		return NULL;
	
	tmp_avp = rad_malloc(sizeof(AVP));
	tmp_avp->attribute = strndup(input, sep_offset);
	tmp_avp->value = strdup(input + sep_offset + 1);
	
	return tmp_avp;
}

ATTR_REQ_IN *proxy_parse_attr_req(char *input, int len)
{
	ATTR_REQ_IN *tmp_attr_req = rad_malloc(sizeof(ATTR_REQ_IN));

	int input_cur = 0;
	int attr_p = 0;
	int item_cur = 0;

	char item_tmp[STR_MAXLEN];

	int state = STATE_TIMESTAMP;

	while(input_cur < len && state <= STATE_LIM)
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
			case STATE_PROVIDED_ATTR_LEN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->provided_attr_len = (int) strtol(item_tmp, NULL, 10);
					tmp_attr_req->provided_attr = rad_malloc(sizeof(AVP) * tmp_attr_req->provided_attr_len);
					
					if (tmp_attr_req->provided_attr_len == 0)
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
			case STATE_PROVIDED_ATTR:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					
					memcpy(tmp_attr_req->provided_attr + (attr_p * sizeof(AVP)), atoavp(item_tmp), sizeof(AVP));
					//tmp_attr_req->provided_attr[attr_p] = atoavp(item_tmp);
               input_cur++;
               bzero(item_tmp, sizeof(char) * STR_MAXLEN);
               item_cur = 0;

					attr_p++;

					if (attr_p >= tmp_attr_req->provided_attr_len)
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
				
				if (tmp_attr_req->requested_attr_len == 0)
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
			if (input[input_cur] == ':')
			{
				item_tmp[item_cur] = '\0';
				
				if (attr_p == 0)
				{
					tmp_attr_req->requested_attr = rad_malloc(sizeof(char *));
					tmp_attr_req->requested_attr[attr_p] = rad_malloc(item_cur + 1);
				}
				else
				{
					tmp_attr_req->requested_attr = realloc(tmp_attr_req->requested_attr, sizeof(char *) * (attr_p + 1));
					tmp_attr_req->requested_attr[attr_p] = rad_malloc(item_cur + 1);
				}
				
				memcpy(tmp_attr_req->requested_attr[attr_p], item_tmp, item_cur + 1);
				attr_p++;
				
				if (attr_p >= tmp_attr_req->requested_attr_len)
				{
					state++;
					attr_p = 0;
				}
				input_cur++;
				bzero(item_tmp, STR_MAXLEN);
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

static AVP *get_avps_by_attributes(AVP *attributes, int length)
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

ATTR_REQ_OUT *get_attr_req_out(ATTR_REQ_IN *input)
{
	ATTR_REQ_OUT *outstruct;
	AVP *pairs;

	outstruct = rad_malloc(sizeof(ATTR_REQ_OUT));
	memset(outstruct, 0, sizeof(ATTR_REQ_OUT));

	pairs = get_avps_by_attributes(input->provided_attr, input->provided_attr_len);
	if (!pairs)
	{
		return NULL;
	}

	outstruct->timestamp = (long) time(0);
	outstruct->servicedn = input->servicedn;
	outstruct->requested_attr_len = input->requested_attr_len;
	outstruct->requested_attr = pairs;

	return outstruct;
}

int attr_req_out_to_string(ATTR_REQ_OUT *input, char **output)
{
	char buffer[STR_MAXLEN];
	int i;
	
	memset(buffer, 0, STR_MAXLEN);
	
	sprintf(buffer, "%lu:%s:%i", input->timestamp, input->servicedn, input->requested_attr_len);
	for (i = 0; i < input->requested_attr_len; i++)
	{
		if (i == input->requested_attr_len - 1)
		{
			sprintf(buffer + strlen(buffer), "%s=%s", input->requested_attr[i].attribute, input->requested_attr[i].value);
		}
		else
		{
			sprintf(buffer + strlen(buffer), "%s=%s:", input->requested_attr[i].attribute, input->requested_attr[i].value);	
		}
	}
	*output = rad_malloc(strlen(buffer));
	strcpy(*output, buffer);
	return strlen(*output);
}

char *obtain_attributes(char *input)
{
	ATTR_REQ_IN *instruct;
	ATTR_REQ_OUT *outstruct;
	char *outmsg;
	
	instruct = proxy_parse_attr_req(input, strlen(input));
	outstruct = get_attr_req_out(instruct);
	attr_req_out_to_string(outstruct, &outmsg);

	return outmsg;
}
