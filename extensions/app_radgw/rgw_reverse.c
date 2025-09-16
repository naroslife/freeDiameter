/*********************************************************************************************************
* Software License Agreement (BSD License)                                                               *
* Author: VoWiFi Migration Team									 *
*													 *
* Copyright (c) 2024										 *
* All rights reserved.											 *
* 													 *
* Redistribution and use of this software in source and binary forms, with or without modification, are  *
* permitted provided that the following conditions are met:						 *
* 													 *
* * Redistributions of source code must retain the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer.										 *
*    													 *
* * Redistributions in binary form must reproduce the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer in the documentation and/or other						 *
*   materials provided with the distribution.								 *
*********************************************************************************************************/

/* 
 * Reverse gateway functionality for app_radgw
 * Handles Diameter -> RADIUS conversion
 */

#include "rgw.h"
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include "test_pool.h"

/* External Oracle initialization status */
//extern int oracle_initialized;

/* Configuration for reverse gateway */
struct rgw_reverse_config {
	int enabled;
	char *radius_server;
	uint16_t radius_port;
	char *radius_secret;
	int secret_len;
	int debug;
};

/* Session tracking for Diameter<->RADIUS correlation */
struct rgw_reverse_session {
	struct fd_list chain;
	char *session_id;
	uint8_t radius_id;
	uint8_t auth_vector[16];
	time_t created;
};

/* Global state */
static struct rgw_reverse_config *g_config = NULL;
static int radius_sockfd = -1;
static struct sockaddr_in radius_addr;
static struct fd_list session_list = FD_LIST_INITIALIZER(session_list);
static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t next_radius_id = 0;
static struct disp_hdl *der_handler_hdl = NULL;

/* Dictionary objects */
static struct {
	struct dict_object *Session_Id;
	struct dict_object *User_Name;
	struct dict_object *Result_Code;
	struct dict_object *EAP_Payload;
	struct dict_object *Origin_Host;
	struct dict_object *Origin_Realm;
	struct dict_object *Auth_Application_Id;
	struct dict_object *Auth_Request_Type;
	struct dict_object *Auth_Session_State;
	struct dict_object *Destination_Realm;
	struct dict_object *SIP_Auth_Data_Item;
	struct dict_object *SIP_Authentication_Scheme;
	struct dict_object *SIP_Number_Auth_Items;
	struct dict_object *Server_Name;
} dict_objs;

/* Initialize dictionary objects */
static int rgw_reverse_dict_init(void)
{
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Session-Id", &dict_objs.Session_Id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "User-Name", &dict_objs.User_Name, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Result-Code", &dict_objs.Result_Code, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "EAP-Payload", &dict_objs.EAP_Payload, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Origin-Host", &dict_objs.Origin_Host, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Origin-Realm", &dict_objs.Origin_Realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Application-Id", &dict_objs.Auth_Application_Id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Request-Type", &dict_objs.Auth_Request_Type, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Session-State", &dict_objs.Auth_Session_State, ENOENT));
	
	// Additional AVPs for MAR (some may not be in base dictionary, handled gracefully)
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "Destination-Realm", &dict_objs.Destination_Realm, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Auth-Data-Item", &dict_objs.SIP_Auth_Data_Item, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Authentication-Scheme", &dict_objs.SIP_Authentication_Scheme, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Number-Auth-Items", &dict_objs.SIP_Number_Auth_Items, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "Server-Name", &dict_objs.Server_Name, ENOENT);
	
	return 0;
}

/* Initialize RADIUS client socket */
static int rgw_reverse_radius_client_init(void)
{
	/* Create UDP socket */
	radius_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (radius_sockfd < 0) {
		TRACE_ERROR("Failed to create RADIUS socket: %s", strerror(errno));
		return -1;
	}
	
	/* Set socket timeout */
	struct timeval tv = {5, 0};  /* 5 second timeout */
	setsockopt(radius_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	
	/* Configure server address */
	memset(&radius_addr, 0, sizeof(radius_addr));
	radius_addr.sin_family = AF_INET;
	radius_addr.sin_port = htons(g_config->radius_port);
	
	if (inet_pton(AF_INET, g_config->radius_server, &radius_addr.sin_addr) != 1) {
		TRACE_ERROR("Invalid RADIUS server address: %s", g_config->radius_server);
		close(radius_sockfd);
		radius_sockfd = -1;
		return -1;
	}
	
	LOG_N("RADIUS client initialized: %s:%d", g_config->radius_server, g_config->radius_port);
	
	return 0;
}

/* Convert Diameter DER to RADIUS Access-Request */
static int rgw_reverse_der_to_radius(struct msg *der, struct radius_msg **rad_msg)
{
	struct radius_msg *msg;
	struct avp *avp;
	struct avp_hdr *hdr;
	char *session_id = NULL;
	char *user_name = NULL;
	uint8_t *eap_payload = NULL;
	size_t eap_len = 0;
	
	/* Create new RADIUS message */
	/*
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, next_radius_id++);
	if (!msg) {
		TRACE_ERROR("Failed to create RADIUS message");
		return -1;
	}
		*/
	
	/* Generate random authenticator */
	/*
	for (int i = 0; i < 16; i++) {
		msg->hdr->authenticator[i] = rand() & 0xFF;
	}
		*/
	
	/* Extract AVPs from Diameter message */
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp, NULL));
	while (avp) {
		CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
		
		if (hdr->avp_code == 263) {  /* Session-Id */
			session_id = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		else if (hdr->avp_code == 1) {  /* User-Name */
			user_name = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
			
			/* Add to RADIUS */
			radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, 
			                    (uint8_t *)user_name, strlen(user_name));
		}
		else if (hdr->avp_code == 462) {  /* EAP-Payload */
			eap_len = hdr->avp_value->os.len;
			eap_payload = malloc(eap_len);
			memcpy(eap_payload, hdr->avp_value->os.data, eap_len);
			
			/* Add EAP-Message (may need fragmentation) */
			size_t offset = 0;
			while (offset < eap_len) {
				size_t chunk = (eap_len - offset) > 253 ? 253 : (eap_len - offset);
				radius_msg_add_attr(msg, RADIUS_ATTR_EAP_MESSAGE,
				                    eap_payload + offset, chunk);
				offset += chunk;
			}
		}
		
		CHECK_FCT(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL));
	}
	
	/* Add NAS attributes */
	uint32_t nas_ip = htonl(0x7F000001);  /* 127.0.0.1 */
	radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS, 
	                    (uint8_t *)&nas_ip, 4);
	
	const char *nas_id = "app_radgw";
	radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IDENTIFIER,
	                    (uint8_t *)nas_id, strlen(nas_id));
	
	/* Add Message-Authenticator for EAP */
	uint8_t msg_auth[16] = {0};
	radius_msg_add_attr(msg, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, msg_auth, 16);
	
	/* Calculate Message-Authenticator using HMAC-MD5 */
	radius_msg_finish_srv(msg, (uint8_t *)g_config->radius_secret,
	                      g_config->secret_len, NULL);
	
	/* Store session */
	if (session_id) {
		struct rgw_reverse_session *sess = calloc(1, sizeof(*sess));
		sess->session_id = strdup(session_id);
		sess->radius_id = msg->hdr->identifier;
		memcpy(sess->auth_vector, msg->hdr->authenticator, 16);
		sess->created = time(NULL);
		
		pthread_mutex_lock(&session_lock);
		fd_list_insert_before(&session_list, &sess->chain);
		pthread_mutex_unlock(&session_lock);
	}
	
	/* Cleanup */
	free(user_name);
	free(session_id);
	free(eap_payload);
	
	*rad_msg = msg;
	
	if (g_config->debug) {
		TRACE_DEBUG(FULL, "Converted DER to RADIUS Access-Request");
	}
	
	return 0;
}

/* Convert RADIUS response to Diameter DEA */
static int rgw_reverse_radius_to_dea(struct radius_msg *rad_msg, struct msg *der, struct msg **dea)
{
	struct msg *ans;
	struct avp *avp;
	union avp_value val;
	int result_code;
	
	/* Create Diameter answer */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, 0));
	ans = der;
	
	/* Determine Result-Code based on RADIUS Code */
	switch (rad_msg->hdr->code) {
		case RADIUS_CODE_ACCESS_ACCEPT:
			result_code = 2001;  /* DIAMETER_SUCCESS */
			break;
		case RADIUS_CODE_ACCESS_REJECT:
			result_code = 4001;  /* DIAMETER_AUTHENTICATION_REJECTED */
			break;
		case RADIUS_CODE_ACCESS_CHALLENGE:
			result_code = 1001;  /* DIAMETER_MULTI_ROUND_AUTH */
			break;
		default:
			result_code = 5002;  /* DIAMETER_UNKNOWN_SESSION_ID */
	}
	
	/* Add Result-Code */
	CHECK_FCT(fd_msg_avp_new(dict_objs.Result_Code, 0, &avp));
	val.u32 = result_code;
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp));
	
	/* Extract and convert EAP-Message to EAP-Payload */
	uint8_t eap_buffer[4096];
	size_t eap_total = 0;
	
	/* Collect all EAP-Message fragments */
	size_t i;
	for (i = 0; i < rad_msg->attr_used; i++) {
		struct radius_attr_hdr *attr = (struct radius_attr_hdr *)
		                                (rad_msg->buf + rad_msg->attr_pos[i]);
		if (attr->type == RADIUS_ATTR_EAP_MESSAGE) {
			size_t len = attr->length - sizeof(*attr);
			memcpy(eap_buffer + eap_total, attr + 1, len);
			eap_total += len;
		}
	}
	
	/* Add EAP-Payload if present */
	if (eap_total > 0) {
		CHECK_FCT(fd_msg_avp_new(dict_objs.EAP_Payload, 0, &avp));
		val.os.data = malloc(eap_total);
		memcpy(val.os.data, eap_buffer, eap_total);
		val.os.len = eap_total;
		CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
		CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp));
	}
	
	*dea = ans;
	
	if (g_config->debug) {
		TRACE_DEBUG(FULL, "Converted RADIUS response to DEA");
	}
	
	return 0;
}

/* Send RADIUS packet and receive response */
static int rgw_reverse_radius_send_recv(struct radius_msg *req, struct radius_msg **resp)
{
	uint8_t *req_buf;
	size_t req_len;
	uint8_t resp_buf[4096];
	ssize_t sent, received;
	
	/* Get request buffer */
	req_buf = (uint8_t *)req->buf;
	req_len = ntohs(req->hdr->length);
	
	/* Send request */
	sent = sendto(radius_sockfd, req_buf, req_len, 0,
	              (struct sockaddr *)&radius_addr, sizeof(radius_addr));
	
	if (sent != req_len) {
		TRACE_ERROR("Failed to send RADIUS request: %s", strerror(errno));
		return -1;
	}
	
	TRACE_DEBUG(FULL, "Sent RADIUS request: %zd bytes", sent);
	
	/* Receive response */
	received = recvfrom(radius_sockfd, resp_buf, sizeof(resp_buf), 0, NULL, NULL);
	
	if (received < 0) {
		TRACE_ERROR("Failed to receive RADIUS response: %s", strerror(errno));
		return -1;
	}
	
	TRACE_DEBUG(FULL, "Received RADIUS response: %zd bytes", received);
	
	/* Parse response - create from buffer */
	*resp = radius_msg_new(0, 0);
	if (!*resp) {
		TRACE_ERROR("Failed to allocate RADIUS response");
		return -1;
	}
	
	/* Copy response data */
	memcpy((*resp)->buf, resp_buf, received);
	(*resp)->buf_used = received;
	(*resp)->hdr = (struct radius_hdr *)(*resp)->buf;
	
	/* Parse attributes */
	if (radius_msg_initialize(*resp, received) < 0) {
		TRACE_ERROR("Failed to parse RADIUS response");
		radius_msg_free(*resp);
		*resp = NULL;
		return -1;
	}
	
	return 0;
}

typedef struct {
    char *response;
    size_t size;
} RestResponse;

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

typedef struct {
	int resultCode;
	char* userName;
	int httpStatusCode;
} VowifiLdapRestResponse;

static void restResponse2VowifiLdapRestResponse(RestResponse* chunk, VowifiLdapRestResponse* response, int httpStatusCode) {
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
}

static int rgw_call_vowifi_ldap_rest_api(char* imsi, VowifiLdapRestResponse* response) {
	CURL *curl;
    CURLcode res;
    RestResponse chunk;
	long http_code = 0;

    chunk.response = malloc(1);  // Initialize memory
    chunk.size = 0;             // No data yet

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

	if (curl) {
        char url[256];
		// TODO konfig
        snprintf(url, sizeof(url), "http://cparuser:cparpass@localhost:8080/isvowifiaccess?imsi=%s", imsi);

        curl_easy_setopt(curl, CURLOPT_URL, url );
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, responseCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		//printf("curl res:%d\n", res);
		//printf("curl http_status code:%ld\n", http_code);
		if (res != CURLE_OK) {
			response->resultCode = -1;
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("Response data size: %zu\n", chunk.size);
            printf("Response data: \n%s\n", chunk.response);
        }
		restResponse2VowifiLdapRestResponse(&chunk, response, http_code);
        curl_easy_cleanup(curl);
	}
    free(chunk.response);
    curl_global_cleanup();
    return 0;
}

//TODO kiszedni a tényleges imsit fqdn nélkül és a kezdeti 0-t i s.
static int get_imsi_from_der(struct msg **msg, struct avp *avp, char** imsi) {
	struct msg *der = *msg;
	struct avp_hdr *hdr;
	struct avp *avp_local;
	char *user_name = NULL;

	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp_local, NULL));
	while (avp_local) {
		CHECK_FCT(fd_msg_avp_hdr(avp_local, &hdr));

		if (hdr->avp_code == 1) {  /* User-Name */
			user_name = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		CHECK_FCT(fd_msg_browse(avp_local, MSG_BRW_NEXT, &avp_local, NULL));
	}
	*imsi = user_name;
	return 0;
}

static int createDeaFromDerAndLdapResponse(struct msg *der, VowifiLdapRestResponse* response, struct msg **dea) {
	struct msg *ans;
	struct avp *avp;
	union avp_value val;
	int result_code;
	
	/* Create Diameter answer */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, 0));
	ans = der;

	switch (response->resultCode) {
		case 1:
			result_code = 2001;  /* DIAMETER_SUCCESS */
			break;
		default:
			result_code = 4001;  /* DIAMETER_AUTHENTICATION_REJECTED */
	}
	
	/* Add Result-Code */
	CHECK_FCT(fd_msg_avp_new(dict_objs.Result_Code, 0, &avp));
	val.u32 = result_code;
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp));
	
	*dea = ans;
	return 0;
}

void get_users_simple() {
    printf("Oracle connection test - checking pool status...\n");
    
    if (!oracle_pool_is_initialized()) {
        printf("ERROR: Oracle pool not initialized\n");
        return;
    }
    
    printf("Oracle pool is initialized and ready for rejected_logons operations\n");
    
    // Simple test query using oracle_query_log_singleton
    const char *sql = "SELECT COUNT(*) FROM rejected_logons WHERE ROWNUM <= 1";
    int result = oracle_query_log_singleton(sql, NULL);
    
    if (result) {
        printf("Successfully executed test query on rejected_logons table\n");
    } else {
        printf("Test query failed\n");
        const char *error = oracle_get_last_error();
        if (error) {
            printf("Oracle error: %s\n", error);
        }
    }
}

//TODO adatbázis oracle log
static int createSessionLog(struct msg *der, struct msg *dea, VowifiLdapRestResponse* response) {
	struct avp *avp;
	struct avp_hdr *hdr;
	char *session_id = NULL;
	char *user_name = NULL;

	/* Oracle database operations - Demonstration of 4 key operations */
	if (oracle_pool_is_initialized()) {
		printf("=== ORACLE DATABASE OPERATIONS: DER PROCESSING ===\n");
		
		

		// Extract session information from DER message
		char *der_session_id = NULL;
		char *der_user_name = NULL;
		char *der_origin_host = NULL;

		
		// Insert session log entry
		printf("0. SESSION_LOG: Inserting DER session log entry...\n");
		int session_log_result = oracle_insert_session_log(
			der_session_id ? der_session_id : "unknown-session",  // session_id
			der_user_name ? der_user_name : "unknown-user",       // user_name
			1.0,                                                   // origin_state_id
			"DER",                                                 // auth_request_type
			der_origin_host ? der_origin_host : "unknown-host",   // calling_station_id
			"192.168.100.1",                                      // ip_address
			"36301234567890",                                     // msisdn
			'Y',                                                  // active
			"vowifi.service",                                     // service_selection
			NULL,                                                 // start_timestamp (NULL for SYSTIMESTAMP)
			response->resultCode == 1 ? "SUCCESS" : "REJECTED",  // termination_cause
			"192.168.100.50"                                     // car_server_ip
		);
		
		if (session_log_result) {
			printf("   ✓ Session log entry inserted successfully\n");
		} else {
			printf("   ! Failed to insert session log entry: %s\n", oracle_get_last_error());
		}
		
		// Query session_logs table for inserted entry
		printf("0.1. SESSION_LOG QUERY: Retrieving inserted session log entry...\n");
		char **session_log_results = NULL;
		int session_log_count = 0;
		char unique_session_log[64];
		snprintf(unique_session_log, sizeof(unique_session_log), "%s", 
		         der_session_id ? der_session_id : "unknown-session");
		
		if (oracle_simple_query("SELECT id || '|' || session_id || '|' || user_name || '|' || NVL(TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS'), 'NULL') || '|' || active || '|' || NVL(termination_cause, 'NULL') FROM session_logs WHERE session_id = :session_id", 
		                       "session_id", unique_session_log, &session_log_results, &session_log_count)) {
			printf("   ✓ Paraméteres session_logs query sikerült - %d sor\n", session_log_count);
			for (int i = 0; i < session_log_count; i++) {
				// Parse the concatenated result: id|session_id|user_name|event_timestamp|active|termination_cause
				char *result_copy = strdup(session_log_results[i]);
				char *id_str = strtok(result_copy, "|");
				char *session_id_str = strtok(NULL, "|");
				char *user_name_str = strtok(NULL, "|");
				char *event_timestamp_str = strtok(NULL, "|");
				char *active_str = strtok(NULL, "|");
				char *termination_cause_str = strtok(NULL, "|");
				
				printf("     Session Log Record %d:\n", i + 1);
				printf("       ID: %s\n", id_str ? id_str : "NULL");
				printf("       Session ID: %s\n", session_id_str ? session_id_str : "NULL");
				printf("       User Name: %s\n", user_name_str ? user_name_str : "NULL");
				printf("       Event Timestamp: %s\n", event_timestamp_str ? event_timestamp_str : "NULL");
				printf("       Active: %s\n", active_str ? active_str : "NULL");
				printf("       Termination Cause: %s\n", termination_cause_str ? termination_cause_str : "NULL");
				free(result_copy);
			}
			oracle_free_simple_query(session_log_results, session_log_count);
		} else {
			printf("   ! Paraméteres session_logs query sikertelen: %s\n", oracle_get_last_error());
		}
		
		// Test with hardcoded values for session_logs table
		printf("   DEBUG: Testing session_logs with hardcoded parameters for existing records...\n");
		oracle_param_t session_hardcoded_params[2];
		char session_hardcoded_session[] = "unknown-session";  // Update this to match existing session_id
		char session_hardcoded_user[] = "unknown-user";       // Update this to match existing user_name
		session_hardcoded_params[0] = oracle_param_string("sessionid", session_hardcoded_session);
		session_hardcoded_params[1] = oracle_param_string("username", session_hardcoded_user);
		
		printf("   DEBUG: Using existing session_logs values - sessionid: '%s', username: '%s'\n", 
			session_hardcoded_session, session_hardcoded_user);

		oracle_query_result_t *session_hardcoded_result = NULL;
		int session_hardcoded_query_result = oracle_query_parameterized(
			"SELECT * FROM session_logs WHERE session_id = :sessionid AND user_name = :username", 
			session_hardcoded_params, 2, &session_hardcoded_result, 100);
		
		printf("   DEBUG: Session_logs hardcoded query returned: %d\n", session_hardcoded_query_result);
		
		if (session_hardcoded_query_result && session_hardcoded_result) {
			printf("   ✓ Session_logs hardcoded parameterized query succeeded - %d rows found\n", session_hardcoded_result->row_count);
			
			for (int h = 0; h < session_hardcoded_result->row_count; h++) {
				printf("     Session_logs hardcoded row %d:\n", h);
				for (int col = 0; col < session_hardcoded_result->column_count; col++) {
					printf("       %s: %s\n", 
						session_hardcoded_result->column_names[col], 
						session_hardcoded_result->rows[h][col] ? session_hardcoded_result->rows[h][col] : "NULL");
				}
			}
			oracle_free_query_result(session_hardcoded_result);
		} else {
			printf("   ! Session_logs hardcoded parameterized query failed: %s\n", oracle_get_last_error());
		}

		// Test UPDATE operation on session_logs table with hardcoded values
		printf("   DEBUG: Testing session_logs UPDATE with hardcoded values...\n");
		double session_update_id = 1.0;  // Update this to match existing ID in session_logs table
		int session_update_result = oracle_update_session_log_fields(
			session_update_id,           // id - change this to existing ID
			"updated-session-123",       // session_id - new value
			"updated-user-456",          // user_name - new value  
			2.0,                         // origin_state_id - new value
			"UPDATED-DER",               // auth_request_type - new value
			"updated-station-789",       // calling_station_id - new value
			"192.168.200.100",           // ip_address - new value
			"36301111222333",            // msisdn - new value
			'N',                         // active - new value
			"updated.service",           // service_selection - new value
			NULL,                        // start_timestamp - don't update
			NULL,                        // stop_timestamp - don't update
			"UPDATED",                   // termination_cause - new value
			"192.168.200.200"            // car_server_ip - new value
		);
		
		if (session_update_result) {
			printf("   ✓ Session_logs UPDATE with hardcoded values succeeded\n");
		} else {
			printf("   ! Session_logs UPDATE with hardcoded values failed: %s\n", oracle_get_last_error());
		}





		// Cleanup extracted strings
		//free(der_session_id);
		//free(der_user_name);
		//free(der_origin_host);

			char **simple_results = NULL;
			int simple_count = 0;
			char unique_session[64];

		
			if (oracle_simple_query("SELECT id || '|' || session_id || '|' || user_name || '|' || NVL(TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS'), 'NULL') FROM rejected_logons WHERE session_id = :session_id", 
			                       "session_id", unique_session, &simple_results, &simple_count)) {
				printf("   ✓ Paraméteres rejected_logons query sikerült - %d sor\n", simple_count);
				for (int i = 0; i < simple_count; i++) {
					// Parse the concatenated result: id|session_id|user_name|created_at
					char *result_copy = strdup(simple_results[i]);
					char *id_str = strtok(result_copy, "|");
					char *session_id_str = strtok(NULL, "|");
					char *user_name_str = strtok(NULL, "|");
					char *created_at_str = strtok(NULL, "|");
					
					printf("     Record %d:\n", i + 1);
					printf("       ID: %s\n", id_str ? id_str : "NULL");
					printf("       Session ID: %s\n", session_id_str ? session_id_str : "NULL");
					printf("       User Name: %s\n", user_name_str ? user_name_str : "NULL");
					printf("       Created At: %s\n", created_at_str ? created_at_str : "NULL");
					free(result_copy);
				}
				oracle_free_simple_query(simple_results, simple_count);
			} else {
				printf("   ! Paraméteres rejected_logons query sikertelen: %s\n", oracle_get_last_error());
			}



		// Generate unique session ID to avoid conflicts (using existing unique_session from above)
		snprintf(unique_session, sizeof(unique_session), "der-test-%ld", time(NULL));
		
		// OPERATION 1: INSERT - Log the incoming DER request
		
		printf("1. INSERT: Logging DER session (ID: %s)\n", unique_session);
		int insert_result = oracle_insert_rejected_logon(
			unique_session,              // session_id (unique)
			"test.user@vowifi.com",      // user_name
			"4001",                      // exp_res_code (initial: auth failure)
			"vowifi.gateway.test",       // origin_host
			"192.168.100.50"            // car_server_ip
		);
		
		if (insert_result) {
			printf("   ✓ DER session logged successfully\n");
			
			// OPERATION 2: UPDATE - Update the inserted record with new information
			printf("2. UPDATE: Frissítés a beszúrt rekordhoz (session_id: %s)\n", unique_session);
			
			// First, query the ID of the inserted record
			char **id_results = NULL;
			int id_count = 0;
			if (oracle_simple_query("SELECT id FROM rejected_logons WHERE session_id = :session_id", 
			                       "session_id", unique_session, &id_results, &id_count)) {
				if (id_count > 0) {
					double record_id = atof(id_results[0]);
					printf("   Found record with ID: %.0f\n", record_id);

					//ide kell egy timestamp számolás Oracle-kompatibilis formátumban
					time_t now = time(NULL);
					struct tm *tm_info = localtime(&now);
					char timestamp[64];
					// Oracle-kompatibilis formátum: DD/MM/YYYY HH24:MI:SS (numerikus formátum)
					strftime(timestamp, sizeof(timestamp), "%d/%m/%Y %H:%M:%S", tm_info);
					printf("   Generated Oracle timestamp: %s\n", timestamp);

					// Now update the record using its ID
					int update_result = oracle_update_rejected_logon(
						record_id,                   // id (double)
						unique_session,              // session_id (unchanged)
						"almaspite2.user@vowifi.com",   // user_name (frissített)
						"2001",                      // exp_res_code (success)
						"vowifi.gateway.updated",    // origin_host (frissített)
						"192.168.100.100"           // car_server_ip (frissített)
					);
					
					if (update_result) {
						printf("   ✓ DER session record updated successfully\n");
						
						// Verify the update by querying the record again
						char **verify_results = NULL;
						int verify_count = 0;
						if (oracle_simple_query("SELECT id || '|' || session_id || '|' || user_name || '|' || NVL(TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS'), 'NULL') || '|' || exp_res_code || '|' || origin_host || '|' || car_server_ip FROM rejected_logons WHERE id = :id", 
						                       "id", id_results[0], &verify_results, &verify_count)) {
							if (verify_count > 0) {
								printf("   Verification query result:\n");
								char *result_copy = strdup(verify_results[0]);
								char *verify_tokens[7];
								char *token = strtok(result_copy, "|");
								int token_count = 0;
								while (token && token_count < 7) {
									verify_tokens[token_count++] = token;
									token = strtok(NULL, "|");
								}
								if (token_count >= 7) {
									printf("     ID: %s\n", verify_tokens[0]);
									printf("     Session ID: %s\n", verify_tokens[1]);
									printf("     User Name: %s\n", verify_tokens[2]);
									printf("     Created At: %s\n", verify_tokens[3]);
									printf("     Exp Res Code: %s\n", verify_tokens[4]);
									printf("     Origin Host: %s\n", verify_tokens[5]);
									printf("     Car Server IP: %s\n", verify_tokens[6]);
								}
								free(result_copy);
							}
							oracle_free_simple_query(verify_results, verify_count);
						} else {
							printf("   ! Failed to verify update: %s\n", oracle_get_last_error());
						}
					} else {
						printf("   ! Failed to update DER session: %s\n", oracle_get_last_error());
					}
				} else {
					printf("   ! No record found with session_id: %s\n", unique_session);
				}
				oracle_free_simple_query(id_results, id_count);
			} else {
				printf("   ! Failed to query record ID: %s\n", oracle_get_last_error());
			}
			
			/*
			// OPERATION 3: DEBUG - Test connection without query
			printf("3. DEBUG: Testing connection without actual query\n");
			if (oracle_pool_is_initialized()) {
				printf("   ✓ Pool is initialized\n");
			} else {
				printf("   ! Pool is NOT initialized\n");
			}
			*/
			
			/*
			// Simple connection test using oracle_query_log_singleton
			const char *test_sql = "SELECT 1 FROM dual";
			int test_result = oracle_query_log_singleton(test_sql, NULL);
			if (test_result) {
				printf("   ✓ Simple SELECT 1 FROM dual succeeded\n");
			} else {
				printf("   ! Simple SELECT 1 FROM dual failed: %s\n", oracle_get_last_error());
			}
			*/
					
			// === EGYSZERŰ PARAMÉTERES LEKÉRDEZÉS TESZT ===
			printf("   === EGYSZERŰ PARAMÉTERES LEKÉRDEZÉS TESZT ===\n");
			
			char **simple_results = NULL;
			int simple_count = 0;
						
			/*
			// 2. Teszt: Paraméteres lekérdezés dual táblán
			printf("   2. Paraméteres query dual táblán...\n");
			if (oracle_simple_query("SELECT :test_param FROM dual", "test_param", "TestValue123", &simple_results, &simple_count)) {
				printf("   ✓ Paraméteres dual query sikerült - %d sor\n", simple_count);
				if (simple_count > 0) {
					printf("     Eredmény: %s\n", simple_results[0]);
				}
				oracle_free_simple_query(simple_results, simple_count);
			} else {
				printf("   ! Paraméteres dual query sikertelen: %s\n", oracle_get_last_error());
			}
			*/
			// 3. Teszt: Paraméteres lekérdezés rejected_logons táblán (id, session_id, user_name, created_at)
			printf("   3. Paraméteres query rejected_logons táblán (session_id: %s)...\n", unique_session);
			if (oracle_simple_query("SELECT id || '|' || session_id || '|' || user_name || '|' || NVL(TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS'), 'NULL') FROM rejected_logons WHERE session_id = :session_id", 
			                       "session_id", unique_session, &simple_results, &simple_count)) {
				printf("   ✓ Paraméteres rejected_logons query sikerült - %d sor\n", simple_count);
				for (int i = 0; i < simple_count; i++) {
					// Parse the concatenated result: id|session_id|user_name|created_at
					char *result_copy = strdup(simple_results[i]);
					char *id_str = strtok(result_copy, "|");
					char *session_id_str = strtok(NULL, "|");
					char *user_name_str = strtok(NULL, "|");
					char *created_at_str = strtok(NULL, "|");
					
					printf("     Record %d:\n", i + 1);
					printf("       ID: %s\n", id_str ? id_str : "NULL");
					printf("       Session ID: %s\n", session_id_str ? session_id_str : "NULL");
					printf("       User Name: %s\n", user_name_str ? user_name_str : "NULL");
					printf("       Created At: %s\n", created_at_str ? created_at_str : "NULL");
					free(result_copy);
				}
				oracle_free_simple_query(simple_results, simple_count);
			} else {
				printf("   ! Paraméteres rejected_logons query sikertelen: %s\n", oracle_get_last_error());
			}
			
			/*
			// 4. Teszt: COUNT query az összes rejected_logons rekordra
			printf("   4. COUNT query az összes rejected_logons rekordra...\n");
			if (oracle_simple_query("SELECT COUNT(*) FROM rejected_logons", NULL, NULL, &simple_results, &simple_count)) {
				printf("   ✓ COUNT query sikerült - %d sor\n", simple_count);
				if (simple_count > 0) {
					printf("     Összes rekord: %s\n", simple_results[0]);
				}
				oracle_free_simple_query(simple_results, simple_count);
			} else {
				printf("   ! COUNT query sikertelen: %s\n", oracle_get_last_error());
			}

			printf("   === EGYSZERŰ PARAMÉTERES LEKÉRDEZÉS TESZT VÉGE ===\n");
			*/
			
			/*
			// Test 1: Simple parameterized query with string parameter
			printf("   Testing parameterized query with string...\n");
			oracle_param_t params1[1];
			params1[0] = oracle_param_string("test_value", "test123");
			
			oracle_query_result_t *result1 = NULL;
			int param_result1 = oracle_query_parameterized(
				"SELECT :test_value AS test_column FROM dual", 
				params1, 1, &result1, 10);
				
			if (param_result1 && result1) {
				printf("   ✓ Parameterized query 1 succeeded - %d rows, %d columns\n", 
					   result1->row_count, result1->column_count);
				if (result1->row_count > 0 && result1->column_count > 0) {
					printf("     Column: %s, Value: %s\n", 
						   result1->column_names[0], result1->rows[0][0]);
				}
				oracle_free_query_result(result1);
			} else {
				printf("   ! Parameterized query 1 failed: %s\n", oracle_get_last_error());
			}
			*/

			/*
			// Test 2: Query rejected_logons with parameters and populate rejected_logon_t structure
			printf("   DEBUG: About to query for session_id: '%s'\n", unique_session);
			
			// First, let's test with a direct non-parameterized query to see if the data is visible
			printf("   DEBUG: Testing direct non-parameterized query first...\n");
			char direct_sql[512];
			snprintf(direct_sql, sizeof(direct_sql), 
				"SELECT session_id, user_name FROM rejected_logons WHERE session_id = '%s' AND ROWNUM <= 3", 
				unique_session);
			printf("   DEBUG: Direct SQL: %s\n", direct_sql);
			
			char **direct_results = NULL;
			int direct_count = 0;
			if (oracle_simple_query(direct_sql, NULL, NULL, &direct_results, &direct_count)) {
				printf("   ✓ Direct query found %d rows\n", direct_count);
				for (int k = 0; k < direct_count; k++) {
					printf("     Direct result %d: %s\n", k, direct_results[k]);
				}
				oracle_free_simple_query(direct_results, direct_count);
			} else {
				printf("   ! Direct query failed: %s\n", oracle_get_last_error());
			}
			*/


			// Test with hardcoded values that should exist in database
			printf("   DEBUG: Testing with hardcoded parameters for existing records...\n");
			oracle_param_t hardcoded_params[2];
			char hardcoded_session[] = "der-test-1757148702";  // Update this to match existing session_id
			char hardcoded_code[] = "4001";             // Update this to match existing exp_res_code
			hardcoded_params[0] = oracle_param_string("sessionid", hardcoded_session);
			hardcoded_params[1] = oracle_param_string("code", hardcoded_code);
			
			printf("   DEBUG: Using existing values - sessionid: '%s', code: '%s'\n", 
				hardcoded_session, hardcoded_code);

			oracle_query_result_t *hardcoded_result = NULL;
			int hardcoded_query_result = oracle_query_parameterized(
				"SELECT * FROM rejected_logons WHERE session_id = :sessionid AND exp_res_code = :code", 
				hardcoded_params, 2, &hardcoded_result, 100);
			
			printf("   DEBUG: Hardcoded query returned: %d\n", hardcoded_query_result);
			
			if (hardcoded_query_result && hardcoded_result) {
				printf("   ✓ Hardcoded parameterized query succeeded - %d rows found\n", hardcoded_result->row_count);
				
				for (int h = 0; h < hardcoded_result->row_count; h++) {
					printf("     Hardcoded row %d:\n", h);
					for (int col = 0; col < hardcoded_result->column_count; col++) {
						printf("       %s: %s\n", 
							hardcoded_result->column_names[col], 
							hardcoded_result->rows[h][col] ? hardcoded_result->rows[h][col] : "NULL");
					}
				}
				oracle_free_query_result(hardcoded_result);
			} else {
				printf("   ! Hardcoded parameterized query failed: %s\n", oracle_get_last_error());
			}
			/*
			// Now test the parameterized version
			printf("   DEBUG: Testing parameterized query...\n");
			oracle_param_t params2[1];
			params2[0] = oracle_param_string("session_id", unique_session);
			
			printf("   DEBUG: Parameter - name: '%s', value: '%s', length: %zu\n", 
				"session_id", unique_session, strlen(unique_session));

			oracle_query_result_t *result2 = NULL;
			int param_result2 = oracle_query_parameterized(
				"SELECT id, session_id, user_name, exp_res_code, origin_host, created_at, car_server_ip FROM rejected_logons WHERE session_id = :session_id AND ROWNUM <= 5", 
				params2, 1, &result2, 5);
			
			printf("   DEBUG: oracle_query_parameterized returned: %d\n", param_result2);
				
			if (param_result2 && result2) {
				printf("   ✓ Parameterized rejected_logons query succeeded - %d rows found\n", result2->row_count);
				
				if (result2->row_count == 0) {
					printf("   ! No rows found - checking if any records exist at all...\n");
					
					// Try a simpler query to see if ANY records exist in the table
					oracle_query_result_t *debug_result = NULL;
					int debug_query = oracle_query_parameterized(
						"SELECT COUNT(*) as total_count FROM rejected_logons", 
						NULL, 0, &debug_result, 1);
					
					if (debug_query && debug_result && debug_result->row_count > 0) {
						printf("   DEBUG: Total records in rejected_logons table: %s\n", 
							   debug_result->rows[0][0]);
						oracle_free_query_result(debug_result);
					}
					
					// Try querying for records with similar session_id pattern
					oracle_param_t debug_params[1];
					debug_params[0] = oracle_param_string("pattern", "der-test-%");
					
					oracle_query_result_t *pattern_result = NULL;
					int pattern_query = oracle_query_parameterized(
						"SELECT session_id FROM rejected_logons WHERE session_id LIKE :pattern AND ROWNUM <= 3", 
						debug_params, 1, &pattern_result, 3);
					
					if (pattern_query && pattern_result) {
						printf("   DEBUG: Found %d records matching pattern 'der-test-%%':\n", pattern_result->row_count);
						for (int j = 0; j < pattern_result->row_count; j++) {
							printf("     - %s\n", pattern_result->rows[j][0]);
						}
						oracle_free_query_result(pattern_result);
					}
				}
				
				// Populate rejected_logon_t structures with the queried data
				for (int i = 0; i < result2->row_count; i++) {
					rejected_logon_t logon_record;
					memset(&logon_record, 0, sizeof(logon_record));
					
					// Parse and populate the structure fields
					if (result2->column_count >= 7) {
						// ID (column 0)
						if (result2->rows[i][0] && strcmp(result2->rows[i][0], "NULL") != 0) {
							logon_record.id = atof(result2->rows[i][0]);
						}
						
						// session_id (column 1)
						if (result2->rows[i][1] && strcmp(result2->rows[i][1], "NULL") != 0) {
							strncpy(logon_record.session_id, result2->rows[i][1], sizeof(logon_record.session_id) - 1);
						}
						
						// user_name (column 2)
						if (result2->rows[i][2] && strcmp(result2->rows[i][2], "NULL") != 0) {
							strncpy(logon_record.user_name, result2->rows[i][2], sizeof(logon_record.user_name) - 1);
						}
						
						// exp_res_code (column 3)
						if (result2->rows[i][3] && strcmp(result2->rows[i][3], "NULL") != 0) {
							strncpy(logon_record.exp_res_code, result2->rows[i][3], sizeof(logon_record.exp_res_code) - 1);
						}
						
						// origin_host (column 4)
						if (result2->rows[i][4] && strcmp(result2->rows[i][4], "NULL") != 0) {
							strncpy(logon_record.origin_host, result2->rows[i][4], sizeof(logon_record.origin_host) - 1);
						}
						
						// created_at (column 5)
						if (result2->rows[i][5] && strcmp(result2->rows[i][5], "NULL") != 0) {
							strncpy(logon_record.created_at, result2->rows[i][5], sizeof(logon_record.created_at) - 1);
						}
						
						// car_server_ip (column 6)
						if (result2->rows[i][6] && strcmp(result2->rows[i][6], "NULL") != 0) {
							strncpy(logon_record.car_server_ip, result2->rows[i][6], sizeof(logon_record.car_server_ip) - 1);
						}
						
						// Display the populated structure
						printf("     Row %d - rejected_logon_t:\n", i);
						printf("       ID: %.0f\n", logon_record.id);
						printf("       Session ID: %s\n", logon_record.session_id);
						printf("       User Name: %s\n", logon_record.user_name);
						printf("       Expected Result Code: %s\n", logon_record.exp_res_code);
						printf("       Origin Host: %s\n", logon_record.origin_host);
						printf("       Created At: %s\n", logon_record.created_at);
						printf("       Car Server IP: %s\n", logon_record.car_server_ip);
					} else {
						printf("     Row %d: Insufficient columns (%d) for complete rejected_logon_t structure\n", 
							   i, result2->column_count);
					}
				}
				oracle_free_query_result(result2);
			} else {
				printf("   ! Parameterized rejected_logons query failed: %s\n", oracle_get_last_error());
			}
			*/
			/*
			// Test 3: Multiple parameter types
			oracle_param_t params3[2];
			params3[0] = oracle_param_string("str_param", "TestUser");
			params3[1] = oracle_param_double("num_param", 42.5);
			
			oracle_query_result_t *result3 = NULL;
			int param_result3 = oracle_query_parameterized(
				"SELECT :str_param AS username, :num_param AS score FROM dual", 
				params3, 2, &result3, 10);
				
			if (param_result3 && result3) {
				printf("   ✓ Multi-parameter query succeeded - %d rows, %d columns\n", 
					   result3->row_count, result3->column_count);
				if (result3->row_count > 0 && result3->column_count >= 2) {
					printf("     Username: %s, Score: %s\n", 
						   result3->rows[0][0], result3->rows[0][1]);
				}
				oracle_free_query_result(result3);
			} else {
				printf("   ! Multi-parameter query failed: %s\n", oracle_get_last_error());
			}
			*/
		} else {
			printf("   ! Failed to insert DER session: %s\n", oracle_get_last_error());
		}
		
		printf("=== Oracle operations completed ===\n");
	} else {
		printf("Oracle connection not available - skipping database operations\n");
	}

	/* Extract AVPs from Diameter message */
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp, NULL));
	while (avp) {
		CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
		
		if (hdr->avp_code == 263) {  /* Session-Id */
			session_id = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		else if (hdr->avp_code == 1) {  /* User-Name */
			user_name = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		
		CHECK_FCT(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL));
	}

	printf("Session log: session_id=%s, user_name=%s, ldap_result=%d, http_status=%d\n", 
		session_id ? session_id : "N/A", 
		user_name ? user_name : "N/A", 
		response->resultCode, 
		response->httpStatusCode);

	free(session_id);
	free(user_name);
	return 0;
}

static int processMultimediaAuthRequest(struct msg *der, char* imsi) {
	struct msg *mar = NULL;
	struct avp *avp;
	union avp_value val;
	struct dict_object *cmd_mar = NULL;
	struct dict_object *app_swx = NULL;
	struct dict_cmd_data cmd_data;
	struct dict_application_data app_data;
	
	// Look up MAR command (Code: 303, 3GPP TS 29.273)
	cmd_data.cmd_code = 303;
	cmd_data.cmd_flag_val = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;
	cmd_data.cmd_flag_mask = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;
	
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R, 
	                   &cmd_data.cmd_code, &cmd_mar, ENOENT) != 0) {
		TRACE_DEBUG(FULL, "MAR command not found in dictionary, creating message manually");
	}
	
	// Look up SWx application (16777265)
	app_data.application_id = 16777265;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
	                   APPLICATION_BY_ID, &app_data.application_id, 
	                   &app_swx, ENOENT) != 0) {
		TRACE_DEBUG(FULL, "SWx application not found in dictionary");
	}
	
	// Create MAR message
	if (cmd_mar) {
		CHECK_FCT(fd_msg_new(cmd_mar, MSGFL_ALLOC_ETEID, &mar));
	} else {
		// Create message manually if dictionary doesn't have MAR
		CHECK_FCT(fd_msg_new(NULL, MSGFL_ALLOC_ETEID, &mar));
		
		// Set command code manually
		struct msg_hdr *hdr;
		CHECK_FCT(fd_msg_hdr(mar, &hdr));
		hdr->msg_code = 303;
		hdr->msg_flags = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;
		hdr->msg_appl = 16777265; // SWx application
	}
	
	// Add Session-Id (copy from DER)
	struct avp *session_avp = NULL;
	struct avp_hdr *session_hdr = NULL;
	
	// Find Session-Id in original DER
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &session_avp, NULL));
	while (session_avp) {
		CHECK_FCT(fd_msg_avp_hdr(session_avp, &session_hdr));
		if (session_hdr->avp_code == 263) { // Session-Id
			break;
		}
		CHECK_FCT(fd_msg_browse(session_avp, MSG_BRW_NEXT, &session_avp, NULL));
	}
	
	if (session_avp) {
		struct avp *new_session_avp;
		CHECK_FCT(fd_msg_avp_new(dict_objs.Session_Id, 0, &new_session_avp));
		val.os.data = malloc(session_hdr->avp_value->os.len);
		memcpy(val.os.data, session_hdr->avp_value->os.data, session_hdr->avp_value->os.len);
		val.os.len = session_hdr->avp_value->os.len;
		CHECK_FCT(fd_msg_avp_setvalue(new_session_avp, &val));
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, new_session_avp));
	}
	
	// Add Auth-Application-Id (SWx = 16777265)
	CHECK_FCT(fd_msg_avp_new(dict_objs.Auth_Application_Id, 0, &avp));
	val.u32 = 16777265;
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	
	// Add Origin-Host
	CHECK_FCT(fd_msg_avp_new(dict_objs.Origin_Host, 0, &avp));
	val.os.data = (uint8_t*)fd_g_config->cnf_diamid;
	val.os.len = strlen(fd_g_config->cnf_diamid);
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	
	// Add Origin-Realm
	CHECK_FCT(fd_msg_avp_new(dict_objs.Origin_Realm, 0, &avp));
	val.os.data = (uint8_t*)fd_g_config->cnf_diamrlm;
	val.os.len = strlen(fd_g_config->cnf_diamrlm);
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	
	// Add Destination-Realm (for HSS)
	struct dict_object *dest_realm_avp = NULL;
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                         "Destination-Realm", &dest_realm_avp, ENOENT));
	CHECK_FCT(fd_msg_avp_new(dest_realm_avp, 0, &avp));
	val.os.data = (uint8_t*)"epc.mnc030.mcc216.3gppnetwork.org"; // TODO: Make configurable
	val.os.len = strlen("epc.mnc030.mcc216.3gppnetwork.org");
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));

	//Add destinatiopn-host
	struct dict_object *dest_host_avp = NULL;
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                         "Destination-Host", &dest_host_avp, ENOENT));
	CHECK_FCT(fd_msg_avp_new(dest_host_avp, 0, &avp));
	val.os.data = (uint8_t*)"hssfe0.epc.mnc030.mcc216.3gppnetwork.org"; // TODO: Make configurable
	val.os.len = strlen("hssfe0.epc.mnc030.mcc216.3gppnetwork.org");
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	
	// Add User-Name (IMSI)
	CHECK_FCT(fd_msg_avp_new(dict_objs.User_Name, 0, &avp));
	val.os.data = (uint8_t*)imsi;
	val.os.len = strlen(imsi);
	CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
	CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	
	// Add SIP-Auth-Data-Item AVP (for EAP-AKA)
	struct dict_object *sip_auth_data_item = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "SIP-Auth-Data-Item", &sip_auth_data_item, ENOENT) == 0) {
		
		CHECK_FCT(fd_msg_avp_new(sip_auth_data_item, 0, &avp));
		
		// Add SIP-Authentication-Scheme (EAP-AKA = 1)
		struct dict_object *sip_auth_scheme = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                   "SIP-Authentication-Scheme", &sip_auth_scheme, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_auth_scheme, 0, &scheme_avp));
			val.os.data = (uint8_t*)"EAP-AKA";
			val.os.len = 7;
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}
		
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	}
	
	// Add SIP-Number-Auth-Items (number of authentication items requested)
	struct dict_object *sip_num_auth_items = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "SIP-Number-Auth-Items", &sip_num_auth_items, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(sip_num_auth_items, 0, &avp));
		val.u32 = 1; // Request 1 authentication vector
		CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	}
	
	/*
	// Add Server-Name (P-CSCF identifier)
	struct dict_object *server_name = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "Server-Name", &server_name, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(server_name, 0, &avp));
		val.os.data = (uint8_t*)"sip:pcscf.vowifi.com"; // TODO: Make configurable
		val.os.len = strlen("sip:pcscf.vowifi.com");
		CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	}
	*/
	printf("Generated MAR message for IMSI: %s\n", imsi);
	
	// Send MAR message to HSS
	// TODO: Implement callback to handle MAA response
	CHECK_FCT(fd_msg_send(&mar, NULL, NULL));
	
	TRACE_DEBUG(FULL, "MAR message sent to HSS");
	
	return 0;
}

/* Diameter DER handler */
static int rgw_reverse_handle_der(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act)
{
	struct msg *der = *msg;
	struct msg *dea = NULL;
	char *imsi = NULL;
	VowifiLdapRestResponse ldapResponse;
	
	TRACE_DEBUG(FULL, "Handling Diameter DER message");
	
	// Initialize LDAP response with default values
	ldapResponse.resultCode = 1;  // Default to success
	ldapResponse.httpStatusCode = 200;
	ldapResponse.userName = NULL;
	
	get_imsi_from_der(msg, avp, &imsi); 
	if (imsi != NULL) {
		// Call LDAP REST API if needed
		// rgw_call_vowifi_ldap_rest_api(imsi, &ldapResponse);
		

	//TODO session insert - 30x test loop
	printf("Starting 30x createSessionLog test loop...\n");
	for (int i = 0; i < 10000; i++) {
		printf("--- Loop iteration %d/30 ---\n", i + 1);
		createSessionLog(der, dea, &ldapResponse);
	}
	printf("Completed 30x createSessionLog test loop.\n");


		//TODO MAR request kiküldése a HSS felé
		processMultimediaAuthRequest(der, imsi);

		createDeaFromDerAndLdapResponse(der, &ldapResponse, &dea);
		if (dea != NULL) {
			/* Send DEA - update msg pointer to point to the DEA */
			*msg = dea;
			CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
			*act = DISP_ACT_CONT;
			return 0;
		}
	}


	/*
	/ * Convert DER to RADIUS Access-Request * /
	ret = rgw_reverse_der_to_radius(der, &rad_req);
	if (ret != 0) {
		TRACE_ERROR("Failed to convert DER to RADIUS");
		goto error;
	}
	
	/ * Send RADIUS request and get response * /
	ret = rgw_reverse_radius_send_recv(rad_req, &rad_resp);
	if (ret != 0) {
		TRACE_ERROR("Failed to communicate with RADIUS server");
		goto error;
	}
	
	/ * Convert RADIUS response to DEA * /
	ret = rgw_reverse_radius_to_dea(rad_resp, der, &dea);
	if (ret != 0) {
		TRACE_ERROR("Failed to convert RADIUS to DEA");
		goto error;
	}
	*/
	
	/* Send DEA */
	//CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
	//*act = DISP_ACT_CONT;
	//return 0;
	
error:
	/* Create error response */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, MSGFL_ANSW_ERROR));
	dea = der;
	
	/* Add error Result-Code */
	struct avp *avp_rc;
	union avp_value val;
	CHECK_FCT(fd_msg_avp_new(dict_objs.Result_Code, 0, &avp_rc));
	val.u32 = 3002;  /* DIAMETER_UNABLE_TO_DELIVER */
	CHECK_FCT(fd_msg_avp_setvalue(avp_rc, &val));
	CHECK_FCT(fd_msg_avp_add(dea, MSG_BRW_LAST_CHILD, avp_rc));
	
	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
	*act = DISP_ACT_CONT;
	return 0;
}

/* Initialize reverse gateway */
int rgw_reverse_init(char *conffile)
{
	struct disp_when when;
	
	LOG_N("Initializing reverse gateway (Diameter->RADIUS)");
	
	/* Allocate config */
	g_config = calloc(1, sizeof(*g_config));
	if (!g_config) {
		TRACE_ERROR("Failed to allocate config");
		return -1;
	}
	
	/* Parse configuration - for now use defaults */
	/* TODO: Parse from conffile */
	g_config->enabled = 1;
	g_config->radius_server = strdup("127.0.0.1");
	g_config->radius_port = 1812;
	g_config->radius_secret = strdup("testing123");
	g_config->secret_len = strlen(g_config->radius_secret);
	g_config->debug = 1;
	
	if (!g_config->enabled) {
		LOG_N("Reverse gateway disabled in configuration");
		return 0;
	}
	
	/* Initialize dictionary */
	CHECK_FCT(rgw_reverse_dict_init());
	
	/* Initialize RADIUS client */
	CHECK_FCT(rgw_reverse_radius_client_init());
	
	/* Register Diameter handler for DER */
	memset(&when, 0, sizeof(when));
	/* when.command and when.app are struct dict_object pointers, need to look them up */
	{
		struct dict_object *cmd_der;
		struct dict_object *app_eap;
		struct dict_application_data app_data;
		struct dict_cmd_data cmd_data;
		
		/* Look up Diameter EAP Application */
		app_data.application_id = 5;
		CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
		                          APPLICATION_BY_ID, &app_data.application_id, 
		                          &app_eap, ENOENT));
		
		/* Look up DER command - it's actually part of the base protocol */
		cmd_data.cmd_code = 268;
		CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, 
		                          CMD_BY_CODE_R, &cmd_data.cmd_code, 
		                          &cmd_der, ENOENT));
		
		when.command = cmd_der;
		when.app = app_eap;
	}
	
	CHECK_FCT(fd_disp_register(rgw_reverse_handle_der, DISP_HOW_CC, 
	                            &when, NULL, &der_handler_hdl));
	
	LOG_N("Reverse gateway initialized successfully");
	
	return 0;
}

/* Cleanup reverse gateway */
void rgw_reverse_fini(void)
{
	if (!g_config) return;
	
	LOG_N("Terminating reverse gateway");
	
	/* Unregister handler */
	if (der_handler_hdl) {
		CHECK_FCT_DO(fd_disp_unregister(&der_handler_hdl, NULL), );
	}
	
	/* Close socket */
	if (radius_sockfd >= 0) {
		close(radius_sockfd);
		radius_sockfd = -1;
	}
	
	/* Clean up sessions */
	pthread_mutex_lock(&session_lock);
	while (!FD_IS_LIST_EMPTY(&session_list)) {
		struct rgw_reverse_session *sess = (struct rgw_reverse_session *)session_list.next;
		fd_list_unlink(&sess->chain);
		free(sess->session_id);
		free(sess);
	}
	pthread_mutex_unlock(&session_lock);
	
	/* Free config */
	free(g_config->radius_server);
	free(g_config->radius_secret);
	free(g_config);
	g_config = NULL;
}