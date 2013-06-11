/*
 TODO:
 get_mime_certificate functie moet nog corresponderen met de mime module. Hierop moet nog gewacht worden omdat de mime module nog niet geheel af is.
 get_mime_message functie moet nog corresponderen met de mime module. Hierop moet ook gewacht worden totdat de mime module af is.
 get_mime_attributes moet nog worden geschreven bij de mime_module
 AVP_PROXY_REQUEST wordt nog niet meegestuurd aan de idp module
 */

//
//  request_handler_preproxy.c
//
//
//  Created by W.A. Miltenburg on 15-05-13.
//
//

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

#include "common.h"
#include "mod_smime.h"
#include "x509_mod.h"
#include "proxymodule.h"

extern X509 *public_certificate;
extern X509 *private_certificate;
extern EVP_PKEY *private_key;

int proxy_handle_request(REQUEST *request)
{
	char *cert_message;
	VALUE_PAIR *vp;
	switch (request->packet->code) //it's allowed to handle multiple requests, the request type is based on radius responses
   {
   	case PW_AUTHENTICATION_REQUEST:
      	pack_mime_cert(public_certificate, &cert_message);
      	VALUE_PAIR *avp_certificate;
      	avp_certificate = pairmake("AVP_CERTIFICATE_RADIUS",
                                       cert_message, T_OP_EQ); //AVP_CERTIFICATE_RADIUS is an AVP that stores the certificate chain
            pairadd(&request->reply->vps, avp_certificate); //add AVP
            return RLM_MODULE_UPDATED;                      //we are basically saying that our AVPs are updated
            
        case PW_AUTHENTICATION_ACK:
            
            vp = request->packet->vps;
            
            do {
                if (vp->attribute == ATTR_SMIME_REQUEST) //detect if AVP_PROXY_REQUEST is sent by the idp module
                {
                    char *message_attributes = unpack_smime_text((char *)vp->data.octets, private_key, private_certificate);
					char *out_message = obtain_attributes(message_attributes);
                    VALUE_PAIR *avp_attributes;
                    avp_attributes = pairmake("AVP_PROXY_ATTRIBUTES",
                                        out_message, T_OP_EQ); //AVP_PROXY_ATTRIBUTES is an AVP that stores the attributes
                    pairadd(&request->reply->vps, avp_attributes); //add AVP
                    return RLM_MODULE_UPDATED;                      //return statement that is needed when AVPs are updated
                }
            } while ((vp = vp -> next) != 0);
            
            
            
            
    }
    
    
}

