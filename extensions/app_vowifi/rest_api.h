#ifndef __REST_API_H
#define __REST_API_H

#include <curl/curl.h>
#include "vowifi.h"

typedef struct {
    char *response;
    size_t size;
} RestResponse;



int call_vowifi_ldap_rest_api(char* imsi, VowifiLdapRestResponse* response);

int restResponse2VowifiLdapRestResponse(RestResponse* chunk, VowifiLdapRestResponse* response, int httpStatusCode);

#endif /* __REST_API_H */