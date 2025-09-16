#include "rest_api.h"
#include <freeDiameter/extension.h>
#include "vowifi.h"

static size_t responseCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    RestResponse *mem = (RestResponse*) userp;

    char *ptr = realloc(mem->response, mem->size + totalSize + 1);
    if (ptr == NULL) {
        printf("Not enough memory to allocate buffer.\n");
        return 0;
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, totalSize);
    mem->size += totalSize;
    mem->response[mem->size] = '\0';

    return totalSize;
}

int restResponse2VowifiLdapRestResponse(RestResponse* chunk, VowifiLdapRestResponse* response, int httpStatusCode) {
	if (chunk->size > 0) {
		response->httpStatusCode = httpStatusCode;
		if (strcmp("1", chunk->response) == 0) {
			response->resultCode = 1;
		} else {
			response->resultCode = 0;
		}
	} else {
		response->resultCode = -1;
		response->httpStatusCode = -1;
	}
    
    //log
    //printf("Response: %d\n", response->resultCode);

    return 0;
}

int call_vowifi_ldap_rest_api(char* imsi, VowifiLdapRestResponse* response) {
	CURL *curl;
    CURLcode res;
    RestResponse chunk;
	long http_code = 0;

    chunk.response = malloc(1); 
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

	if (curl) {
        char url[500];
        snprintf(url, sizeof(url), (const char*)vowifiConfig.ldapRestUrl, imsi);


        //log
        printf("fullURL: %s\n", url);

        curl_easy_setopt(curl, CURLOPT_URL, url );
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, responseCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (res != CURLE_OK) {
			response->resultCode = -1;
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            //printf("Response data size: %zu\n", chunk.size);
            //printf("Response data: \n%s\n", chunk.response);
        }
		restResponse2VowifiLdapRestResponse(&chunk, response, http_code);

        //log
        printf("LDAP proxy %s answered \n", vowifiConfig.ldapRestUrl);
        printf("Response: %d\n", response->resultCode);
        
        curl_easy_cleanup(curl);
	}
    free(chunk.response);
    curl_global_cleanup();
    return 0;
}