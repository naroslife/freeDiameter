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
	LOG_N("REVERSE GATEWAY: Creating RADIUS message");
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, next_radius_id++);
	if (!msg) {
		LOG_E("REVERSE GATEWAY ERROR: Failed to create RADIUS message");
		TRACE_ERROR("Failed to create RADIUS message");
		return -1;
	}
	LOG_N("REVERSE GATEWAY: RADIUS message created successfully");
	
	/* Generate random authenticator */
	for (int i = 0; i < 16; i++) {
		msg->hdr->authenticator[i] = rand() & 0xFF;
	}
	
	/* Extract AVPs from Diameter message */
	LOG_N("REVERSE GATEWAY: Extracting AVPs from Diameter message");
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp, NULL));
	while (avp) {
		CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
		LOG_N("REVERSE GATEWAY: Processing AVP code %d", hdr->avp_code);
		
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
	
	/* Calculate Message-Authenticator using HMAC-MD5 */
	/* Note: radius_msg_finish will add Message-Authenticator automatically */
	LOG_N("REVERSE GATEWAY: Finishing RADIUS message with Message-Authenticator");
	radius_msg_finish(msg, (uint8_t *)g_config->radius_secret,
	                  g_config->secret_len);
	LOG_N("REVERSE GATEWAY: RADIUS message finished, storing session");
	
	/* Store session */
	if (session_id) {
		struct rgw_reverse_session *sess = calloc(1, sizeof(*sess));
		fd_list_init(&sess->chain, sess);  /* Initialize the list chain */
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
	
	LOG_N("REVERSE GATEWAY: Successfully converted DER to RADIUS");
	if (g_config->debug) {
		TRACE_DEBUG(FULL, "Converted DER to RADIUS Access-Request");
	}
	
	return 0;
}

// /* Convert MAA to RADIUS Access-Challenge with auth vectors */
// static int rgw_reverse_maa_to_radius(struct msg *maa, struct radius_msg **rad_msg)
// {
// 	struct avp *avp = NULL;
// 	struct radius_msg *msg;
// 	char *session_id = NULL;
// 	char *user_name = NULL;
	
// 	LOG_N("REVERSE GATEWAY: Converting MAA to RADIUS Access-Challenge");
	
// 	/* Create RADIUS Access-Challenge message */
// 	msg = radius_msg_new(RADIUS_CODE_ACCESS_CHALLENGE, next_radius_id++);
// 	if (!msg) {
// 		TRACE_ERROR("Failed to create RADIUS message");
// 		return -1;
// 	}
	
// 	/* Process MAA AVPs */
// 	CHECK_FCT(fd_msg_browse(maa, MSG_BRW_FIRST_CHILD, &avp, NULL));
	
// 	while (avp) {
// 		struct avp_hdr *avp_hdr;
		
// 		CHECK_FCT(fd_msg_avp_hdr(avp, &avp_hdr));
		
// 		LOG_N("REVERSE GATEWAY: Processing MAA AVP code %u", avp_hdr->avp_code);
		
// 		switch (avp_hdr->avp_code) {
// 			case 263:  /* Session-Id */
// 				session_id = strndup((char *)avp_hdr->avp_value->os.data, avp_hdr->avp_value->os.len);
// 				/* Add State attribute with session ID */
// 				radius_msg_add_attr(msg, 24, (uint8_t *)session_id, strlen(session_id));
// 				break;
				
// 			case 1:  /* User-Name */
// 				user_name = strndup((char *)avp_hdr->avp_value->os.data, avp_hdr->avp_value->os.len);
// 				radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, 
// 				                    (uint8_t *)user_name, strlen(user_name));
// 				break;
				
// 			case 612:  /* SIP-Auth-Data-Item (grouped) */
// 			{
// 				/* Browse into grouped AVP */
// 				struct avp *sip_item = NULL;
// 				CHECK_FCT(fd_msg_browse(avp, MSG_BRW_FIRST_CHILD, &sip_item, NULL));
				
// 				uint8_t *rand_val = NULL, *autn_val = NULL, *xres_val = NULL;
// 				size_t rand_len = 0, autn_len = 0, xres_len = 0;
				
// 				while (sip_item) {
// 					struct avp_hdr *sip_hdr;
					
// 					CHECK_FCT(fd_msg_avp_hdr(sip_item, &sip_hdr));
					
// 					switch (sip_hdr->avp_code) {
// 						case 608:  /* SIP-Authentication-Scheme */
// 							/* Should be "EAP-AKA" */
// 							LOG_N("REVERSE GATEWAY: Auth scheme: %.*s", 
// 							      (int)sip_hdr->avp_value->os.len, sip_hdr->avp_value->os.data);
// 							break;
							
// 						case 609:  /* SIP-Authenticate */
// 							/* Contains RAND||AUTN */
// 							if (sip_hdr->avp_value->os.len >= 32) {
// 								rand_val = sip_hdr->avp_value->os.data;
// 								rand_len = 16;
// 								autn_val = sip_hdr->avp_value->os.data + 16;
// 								autn_len = 16;
// 								LOG_N("REVERSE GATEWAY: Got RAND (16 bytes) and AUTN (16 bytes)");
// 							}
// 							break;
							
// 						case 610:  /* SIP-Authorization */
// 							/* Contains XRES */
// 							xres_val = sip_hdr->avp_value->os.data;
// 							xres_len = sip_hdr->avp_value->os.len;
// 							LOG_N("REVERSE GATEWAY: Got XRES (%zu bytes)", xres_len);
// 							break;
// 					}
					
// 					/* Get next SIP AVP */
// 					CHECK_FCT(fd_msg_browse(sip_item, MSG_BRW_NEXT, &sip_item, NULL));
// 				}
				
// 				/* Add auth vectors as Vendor-Specific Attributes */
// 				if (rand_val && autn_val) {
// 					/* Vendor-Specific format: vendor-id (4 bytes) + vendor-type (1 byte) + data */
// 					uint8_t vsa_buf[255];
// 					size_t vsa_len;
					
// 					/* 3GPP Vendor ID = 10415 */
// 					uint32_t vendor_id = htonl(10415);
					
// 					/* Add RAND as VSA type 1 */
// 					vsa_len = 0;
// 					memcpy(vsa_buf + vsa_len, &vendor_id, 4);
// 					vsa_len += 4;
// 					vsa_buf[vsa_len++] = 1;  /* Type for RAND */
// 					vsa_buf[vsa_len++] = rand_len + 2;  /* Length including type and length */
// 					memcpy(vsa_buf + vsa_len, rand_val, rand_len);
// 					vsa_len += rand_len;
// 					radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, vsa_buf, vsa_len);
					
// 					/* Add AUTN as VSA type 2 */
// 					vsa_len = 0;
// 					memcpy(vsa_buf + vsa_len, &vendor_id, 4);
// 					vsa_len += 4;
// 					vsa_buf[vsa_len++] = 2;  /* Type for AUTN */
// 					vsa_buf[vsa_len++] = autn_len + 2;
// 					memcpy(vsa_buf + vsa_len, autn_val, autn_len);
// 					vsa_len += autn_len;
// 					radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, vsa_buf, vsa_len);
					
// 					/* Add XRES as VSA type 3 (for server to verify later) */
// 					if (xres_val) {
// 						vsa_len = 0;
// 						memcpy(vsa_buf + vsa_len, &vendor_id, 4);
// 						vsa_len += 4;
// 						vsa_buf[vsa_len++] = 3;  /* Type for XRES */
// 						vsa_buf[vsa_len++] = xres_len + 2;
// 						memcpy(vsa_buf + vsa_len, xres_val, xres_len);
// 						vsa_len += xres_len;
// 						radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, vsa_buf, vsa_len);
// 					}
// 				}
// 				break;
// 			}
			
// 			case 268:  /* Result-Code */
// 				/* Check if authentication was successful */
// 				if (avp_hdr->avp_value->u32 != 2001) {
// 					LOG_E("REVERSE GATEWAY: MAA indicates failure, Result-Code=%u", avp_hdr->avp_value->u32);
// 					/* Convert to Access-Reject instead */
// 					radius_msg_set_hdr(msg, RADIUS_CODE_ACCESS_REJECT, msg->hdr->identifier);
// 				}
// 				break;
// 		}
		
// 		/* Get next AVP */
// 		CHECK_FCT(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL));
// 	}
	
// 	/* Add NAS attributes */
// 	uint32_t nas_ip = inet_addr("127.0.0.1");
// 	radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS, 
// 	                    (uint8_t *)&nas_ip, 4);
// 	radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT, 0);
	
// 	const char *nas_id = "freediameter-maa";
// 	radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IDENTIFIER, 
// 	                    (uint8_t *)nas_id, strlen(nas_id));
	
// 	/* Add Message-Authenticator */
// 	radius_msg_add_attr(msg, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
// 	                    (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
	
// 	/* Finish message */
// 	LOG_N("REVERSE GATEWAY: Finishing RADIUS message with Message-Authenticator");
// 	radius_msg_finish(msg, (uint8_t *)g_config->radius_secret,
// 	                  g_config->secret_len);
	
// 	/* Store session for response matching */
// 	if (session_id) {
// 		struct rgw_reverse_session *sess = calloc(1, sizeof(*sess));
// 		fd_list_init(&sess->chain, sess);
// 		sess->session_id = strdup(session_id);
// 		sess->radius_id = msg->hdr->identifier;
// 		memcpy(sess->auth_vector, msg->hdr->authenticator, 16);
// 		sess->created = time(NULL);
		
// 		pthread_mutex_lock(&session_lock);
// 		fd_list_insert_before(&session_list, &sess->chain);
// 		pthread_mutex_unlock(&session_lock);
// 	}
	
// 	/* Cleanup */
// 	free(user_name);
// 	free(session_id);
	
// 	*rad_msg = msg;
	
// 	LOG_N("REVERSE GATEWAY: Successfully converted MAA to RADIUS Access-Challenge");
	
// 	return 0;
// }

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
	
	/* Return the answer */
	*dea = ans;
	
	if (g_config->debug) {
		TRACE_DEBUG(FULL, "Converted RADIUS response to DEA");
	}
	
	return 0;
}

/* Helper function to get RADIUS code name */
static const char* radius_code_name(uint8_t code)
{
	switch (code) {
		case RADIUS_CODE_ACCESS_REQUEST: return "Access-Request";
		case RADIUS_CODE_ACCESS_ACCEPT: return "Access-Accept";
		case RADIUS_CODE_ACCESS_REJECT: return "Access-Reject";
		case RADIUS_CODE_ACCOUNTING_REQUEST: return "Accounting-Request";
		case RADIUS_CODE_ACCOUNTING_RESPONSE: return "Accounting-Response";
		case RADIUS_CODE_ACCESS_CHALLENGE: return "Access-Challenge";
		case RADIUS_CODE_STATUS_SERVER: return "Status-Server";
		case RADIUS_CODE_STATUS_CLIENT: return "Status-Client";
		case 40: return "Disconnect-Request";  /* RFC 3576 */
		case 41: return "Disconnect-ACK";
		case 42: return "Disconnect-NAK";
		case 43: return "CoA-Request";
		case 44: return "CoA-ACK";
		case 45: return "CoA-NAK";
		default: return "Unknown";
	}
}

/* Helper function to log RADIUS message details */
static void log_radius_message(const char *direction, struct radius_msg *msg)
{
	if (!msg || !msg->hdr) return;
	
	LOG_N("REVERSE GATEWAY: %s RADIUS Message:", direction);
	LOG_N("  Code: %d (%s)", msg->hdr->code, radius_code_name(msg->hdr->code));
	LOG_N("  Identifier: %d", msg->hdr->identifier);
	LOG_N("  Length: %d bytes", ntohs(msg->hdr->length));
	
	/* Log key attributes */
	for (size_t i = 0; i < msg->attr_used; i++) {
		struct radius_attr_hdr *attr = (struct radius_attr_hdr *)
		                                (msg->buf + msg->attr_pos[i]);
		switch (attr->type) {
			case RADIUS_ATTR_USER_NAME:
				LOG_N("  User-Name: %.*s", attr->length - 2, (char *)(attr + 1));
				break;
			case RADIUS_ATTR_NAS_IP_ADDRESS:
				{
					uint32_t ip;
					memcpy(&ip, attr + 1, 4);
					struct in_addr addr;
					addr.s_addr = ip;
					LOG_N("  NAS-IP-Address: %s", inet_ntoa(addr));
				}
				break;
			case RADIUS_ATTR_NAS_IDENTIFIER:
				LOG_N("  NAS-Identifier: %.*s", attr->length - 2, (char *)(attr + 1));
				break;
			case RADIUS_ATTR_EAP_MESSAGE:
				LOG_N("  EAP-Message: %d bytes", attr->length - 2);
				break;
			case RADIUS_ATTR_MESSAGE_AUTHENTICATOR:
				LOG_N("  Message-Authenticator: present");
				break;
			case RADIUS_ATTR_STATE:
				LOG_N("  State: %d bytes", attr->length - 2);
				break;
		}
	}
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
	
	/* Log outgoing request details */
	log_radius_message("Sending", req);
	
	/* Send request */
	LOG_N("REVERSE GATEWAY: Sending RADIUS %s to %s:%d (fd=%d, %zu bytes)",
	      radius_code_name(req->hdr->code),
	      inet_ntoa(radius_addr.sin_addr), ntohs(radius_addr.sin_port),
	      radius_sockfd, req_len);
	sent = sendto(radius_sockfd, req_buf, req_len, 0,
	              (struct sockaddr *)&radius_addr, sizeof(radius_addr));
	
	if (sent < 0) {
		LOG_E("REVERSE GATEWAY ERROR: sendto failed: %s (errno=%d)", strerror(errno), errno);
		TRACE_ERROR("Failed to send RADIUS request: %s", strerror(errno));
		return -1;
	}
	if (sent != req_len) {
		LOG_E("REVERSE GATEWAY ERROR: Partial send: sent %zd of %zu bytes", sent, req_len);
		TRACE_ERROR("Failed to send complete RADIUS request: sent %zd of %zu", sent, req_len);
		return -1;
	}
	
	LOG_N("REVERSE GATEWAY: Successfully sent RADIUS request: %zd bytes", sent);
	TRACE_DEBUG(FULL, "Sent RADIUS request: %zd bytes", sent);
	
	/* Receive response */
	LOG_N("REVERSE GATEWAY: Waiting for RADIUS response...");
	struct sockaddr_in from_addr;
	socklen_t from_len = sizeof(from_addr);
	int retries = 6;
	int retry_count = 0;
	
	do {
		LOG_N("REVERSE GATEWAY: Attempt %d/%d to receive RADIUS response", 
			  retry_count + 1, retries);
		received = recvfrom(radius_sockfd, resp_buf, sizeof(resp_buf), 0, 
							(struct sockaddr *)&from_addr, &from_len);
		
		if (received < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				LOG_N("REVERSE GATEWAY: Timeout on attempt %d", retry_count + 1);
				retry_count++;
				if (retry_count < retries) {
					usleep(100000); /* Wait 100ms before retry */
					continue;
				}
			}
			break;
		}
		
		/* Verify response is from correct server */
		if (from_addr.sin_addr.s_addr != radius_addr.sin_addr.s_addr ||
			from_addr.sin_port != radius_addr.sin_port) {
			LOG_N("REVERSE GATEWAY: Response from unexpected source, ignoring");
			retry_count++;
			continue;
		}
		
		/* Valid response received */
		break;
		
	} while (retry_count < retries);
	
	if (received < 0) {
		LOG_E("REVERSE GATEWAY ERROR: recvfrom failed: %s (errno=%d)", strerror(errno), errno);
		TRACE_ERROR("Failed to receive RADIUS response: %s", strerror(errno));
		return -1;
	}
	
	LOG_N("REVERSE GATEWAY: Received RADIUS response: %zd bytes, code=%d (%s)", 
	      received, resp_buf[0], radius_code_name(resp_buf[0]));
	TRACE_DEBUG(FULL, "Received RADIUS response: %zd bytes", received);
	
	/* Allocate RADIUS message structure */
	*resp = malloc(sizeof(struct radius_msg));
	if (!*resp) {
		TRACE_ERROR("Failed to allocate RADIUS response structure");
		return -1;
	}
	memset(*resp, 0, sizeof(struct radius_msg));
	
	/* Initialize the message structure with the correct size */
	if (radius_msg_initialize(*resp, received) < 0) {
		TRACE_ERROR("Failed to initialize RADIUS response");
		free(*resp);
		*resp = NULL;
		return -1;
	}
	
	/* Copy the received data into the allocated buffer */
	memcpy((*resp)->buf, resp_buf, received);
	(*resp)->buf_size = (*resp)->buf_used = received;
	(*resp)->hdr = (struct radius_hdr *)(*resp)->buf;
	
	/* Parse attributes */
	unsigned char *pos = (unsigned char *)((*resp)->hdr + 1);
	unsigned char *end = (*resp)->buf + (*resp)->buf_used;
	struct radius_attr_hdr *attr;
	
	while (pos < end) {
		if ((size_t)(end - pos) < sizeof(*attr)) {
			TRACE_ERROR("RADIUS message attribute truncated");
			radius_msg_free(*resp);
			free(*resp);
			*resp = NULL;
			return -1;
		}
		
		attr = (struct radius_attr_hdr *)pos;
		if (pos + attr->length > end || attr->length < sizeof(*attr)) {
			TRACE_ERROR("Invalid RADIUS attribute length");
			radius_msg_free(*resp);
			free(*resp);
			*resp = NULL;
			return -1;
		}
		
		/* Store attribute position */
		if ((*resp)->attr_used >= (*resp)->attr_size) {
			/* Need to resize attribute array */
			size_t new_size = (*resp)->attr_size * 2;
			size_t *new_pos = realloc((*resp)->attr_pos, new_size * sizeof(size_t));
			if (!new_pos) {
				TRACE_ERROR("Failed to resize attribute array");
				radius_msg_free(*resp);
				free(*resp);
				*resp = NULL;
				return -1;
			}
			(*resp)->attr_pos = new_pos;
			(*resp)->attr_size = new_size;
		}
		
		(*resp)->attr_pos[(*resp)->attr_used++] = pos - (*resp)->buf;
		pos += attr->length;
	}
	
	/* Log received response details */
	log_radius_message("Received", *resp);

	return 0;
}
// PSEUDO
// challenge_to_radius_cb() {

// 	diameter_uzenet_challengere_a_valasz;

// 	auto radius_challenge_valasz = convert_to_radius(diameter_uzenet_challengere_a_valasz);
// 	rgw_reverse_radius_send_recv(radius_challenge_valasz, &rad_resp);

// }

// PSEUDO
// maa_callback() {
// 	maa answer;
// 	maa_to_valamilyen_radius(radius_msg);
// 	rgw_reverse_radius_send_recv(radius_msg, &rad_resp);
// 	if (van challenge) {
// 		create_challenge_diameter_answer(der, dia_challenge_ans);
// 		fd_msg_send(dia_challenge_ans, challenge_to_radius_cb)
// 	}
// }

/* Diameter DER handler */
static int rgw_reverse_handle_der(struct msg **msg, struct avp *avp,
								  struct session *sess, void *opaque,
								  enum disp_action *act)
{
	struct msg *der = *msg;
	struct msg *dea = NULL;
	struct radius_msg *rad_req = NULL;
	struct radius_msg *rad_resp = NULL;
	int ret;
	
	LOG_N("REVERSE GATEWAY: Received DER message for processing");
	TRACE_DEBUG(FULL, "Handling Diameter DER message");
	
	/* Convert DER to RADIUS Access-Request */
	LOG_N("REVERSE GATEWAY: Converting DER to RADIUS Access-Request");
	ret = rgw_reverse_der_to_radius(der, &rad_req);
	if (ret != 0) {
		LOG_E("REVERSE GATEWAY ERROR: Failed to convert DER to RADIUS (ret=%d)", ret);
		TRACE_ERROR("Failed to convert DER to RADIUS");
		goto error;
	}
	LOG_N("REVERSE GATEWAY: Successfully converted DER to RADIUS");
	
	/* Send RADIUS request and get response */
	LOG_N("REVERSE GATEWAY: Calling rgw_reverse_radius_send_recv");
	ret = rgw_reverse_radius_send_recv(rad_req, &rad_resp);

	// PSEUDO
	// if (rad_resp == kerjel hsstol) {
	// 	create_mar(mar);
	// 	fd_msg_send(mar, maa_callback());
	// }


	if (ret != 0) {
		LOG_E("REVERSE GATEWAY ERROR: Failed to communicate with RADIUS server (ret=%d)", ret);
		TRACE_ERROR("Failed to communicate with RADIUS server");
		goto error;
	}
	LOG_N("REVERSE GATEWAY: Got RADIUS response, converting to DEA");
	
	/* Convert RADIUS response to DEA */
	ret = rgw_reverse_radius_to_dea(rad_resp, der, &dea);
	if (ret != 0) {
		LOG_E("REVERSE GATEWAY ERROR: Failed to convert RADIUS to DEA (ret=%d)", ret);
		TRACE_ERROR("Failed to convert RADIUS to DEA");
		goto error;
	}
	LOG_N("REVERSE GATEWAY: Successfully converted RADIUS to DEA");
	
	/* Update the message pointer to point to the answer */
	*msg = dea;
	
	/* Send DEA */
	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
	/* Cleanup */
	if (rad_req) {
		LOG_N("REVERSE GATEWAY: Cleaning up RADIUS request");
		radius_msg_free(rad_req);
	}
	if (rad_resp) {
		LOG_N("REVERSE GATEWAY: Cleaning up RADIUS response");
		radius_msg_free(rad_resp);
	}
	
	LOG_N("REVERSE GATEWAY: Successfully processed DER -> DEA conversion");
	
	*act = DISP_ACT_CONT;
	return 0;
	
error:
	/* Create error response */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, MSGFL_ANSW_ERROR));
	*msg = der;  /* Update message pointer to the answer */
	
	/* Add error Result-Code */
	struct avp *avp_rc;
	union avp_value val;
	CHECK_FCT(fd_msg_avp_new(dict_objs.Result_Code, 0, &avp_rc));
	val.u32 = 3002;  /* DIAMETER_UNABLE_TO_DELIVER */
	CHECK_FCT(fd_msg_avp_setvalue(avp_rc, &val));
	CHECK_FCT(fd_msg_avp_add(*msg, MSG_BRW_LAST_CHILD, avp_rc));
	
	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
	if (rad_req) {
		LOG_E("REVERSE GATEWAY: Cleaning up RADIUS request");
		radius_msg_free(rad_req);
	}
	if (rad_resp) {
		LOG_E("REVERSE GATEWAY: Cleaning up RADIUS response");
		radius_msg_free(rad_resp);
	}
	
	LOG_N("REVERSE GATEWAY: Unsuccessfully processed DER -> DEA conversion");
	
	*act = DISP_ACT_CONT;
	return 0;
}

/* Diameter maa handler */
// static int rgw_reverse_handle_maa(struct msg **msg, struct avp *avp,
// 								  struct session *sess, void *opaque,
// 								  enum disp_action *act)
// {
// 	struct msg *der = *msg;
// 	struct msg *dea = NULL;
// 	struct radius_msg *rad_req = NULL;
// 	struct radius_msg *rad_resp = NULL;
// 	int ret;
	
// 	LOG_N("REVERSE GATEWAY: Received maa message for processing");
// 	TRACE_DEBUG(FULL, "Handling Diameter maa message");
	
// 	/* Convert MAA to RADIUS Access-Challenge */
// 	LOG_N("REVERSE GATEWAY: Converting MAA to RADIUS Access-Challenge");
// 	ret = rgw_reverse_maa_to_radius(der, &rad_req);
// 	if (ret != 0) {
// 		LOG_E("REVERSE GATEWAY ERROR: Failed to convert DER to RADIUS (ret=%d)", ret);
// 		TRACE_ERROR("Failed to convert DER to RADIUS");
// 		goto error;
// 	}
// 	LOG_N("REVERSE GATEWAY: Successfully converted DER to RADIUS");
	
// 	/* Send RADIUS request and get response */
// 	LOG_N("REVERSE GATEWAY: Calling rgw_reverse_radius_send_recv");
// 	ret = rgw_reverse_radius_send_recv(rad_req, &rad_resp);
// 	if (ret != 0) {
// 		LOG_E("REVERSE GATEWAY ERROR: Failed to communicate with RADIUS server (ret=%d)", ret);
// 		TRACE_ERROR("Failed to communicate with RADIUS server");
// 		goto error;
// 	}
// 	LOG_N("REVERSE GATEWAY: Got RADIUS response, converting to DEA");
	
// 	/* Convert RADIUS response to DEA */
// 	ret = rgw_reverse_radius_to_dea(rad_resp, der, &dea);
// 	if (ret != 0) {
// 		LOG_E("REVERSE GATEWAY ERROR: Failed to convert RADIUS to DEA (ret=%d)", ret);
// 		TRACE_ERROR("Failed to convert RADIUS to DEA");
// 		goto error;
// 	}
// 	LOG_N("REVERSE GATEWAY: Successfully converted RADIUS to DEA");
	
// 	/* Update the message pointer to point to the answer */
// 	*msg = dea;
	
// 	/* Send DEA */
// 	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
// 	/* Cleanup */
// 	if (rad_req) {
// 		LOG_N("REVERSE GATEWAY: Cleaning up RADIUS request");
// 		radius_msg_free(rad_req);
// 	}
// 	if (rad_resp) {
// 		LOG_N("REVERSE GATEWAY: Cleaning up RADIUS response");
// 		radius_msg_free(rad_resp);
// 	}
	
// 	LOG_N("REVERSE GATEWAY: Successfully processed DER -> DEA conversion");
	
// 	*act = DISP_ACT_CONT;
// 	return 0;
	
// error:
// 	/* Create error response */
// 	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, MSGFL_ANSW_ERROR));
// 	*msg = der;  /* Update message pointer to the answer */
	
// 	/* Add error Result-Code */
// 	struct avp *avp_rc;
// 	union avp_value val;
// 	CHECK_FCT(fd_msg_avp_new(dict_objs.Result_Code, 0, &avp_rc));
// 	val.u32 = 3002;  /* DIAMETER_UNABLE_TO_DELIVER */
// 	CHECK_FCT(fd_msg_avp_setvalue(avp_rc, &val));
// 	CHECK_FCT(fd_msg_avp_add(*msg, MSG_BRW_LAST_CHILD, avp_rc));
	
// 	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
// 	if (rad_req) {
// 		LOG_E("REVERSE GATEWAY: Cleaning up RADIUS request");
// 		radius_msg_free(rad_req);
// 	}
// 	if (rad_resp) {
// 		LOG_E("REVERSE GATEWAY: Cleaning up RADIUS response");
// 		radius_msg_free(rad_resp);
// 	}
	
// 	LOG_N("REVERSE GATEWAY: Unsuccessfully processed DER -> DEA conversion");
	
// 	*act = DISP_ACT_CONT;
// 	return 0;
// }


static int rgw_reverse_register_der_handler(struct disp_when *when)
{
	/* Register Diameter handler for DER */
	memset(when, 0, sizeof(*when));
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
		
		when->command = cmd_der;
		when->app = app_eap;
	}
	
	return 0;
}

// static int rgw_reverse_register_maa_handler(struct disp_when *when)
// {
// 	/* Register Diameter handler for maa */
// 	memset(when, 0, sizeof(*when));
// 	/* when.command and when.app are struct dict_object pointers, need to look them up */
// 	{
// 		struct dict_object *cmd_maa;
// 		struct dict_object *app_eap;
// 		struct dict_application_data app_data;
// 		struct dict_cmd_data cmd_data;
		
// 		/* Look up Diameter EAP Application */
// 		app_data.application_id = 5;
// 		CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
// 		                          APPLICATION_BY_ID, &app_data.application_id, 
// 		                          &app_eap, ENOENT));
		
// 		/* Look up MAA command - code 303 */
// 		cmd_data.cmd_code = 303;
// 		CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, 
// 		                          CMD_BY_CODE_A, &cmd_data.cmd_code, 
// 		                          &cmd_maa, ENOENT));
		
// 		when->command = cmd_maa;
// 		when->app = app_eap;
// 	}
	
	
// 	return 0;
// }

/* Initialize reverse gateway */
int rgw_reverse_init(char *conffile) {
	
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

	// Register handlers
	struct disp_when when;
	rgw_reverse_register_der_handler(&when);

	CHECK_FCT(fd_disp_register(rgw_reverse_handle_der, DISP_HOW_CC,
							   &when, NULL, &der_handler_hdl));

	/* MAA handler registration disabled for now - needs proper 3GPP dictionary 
	rgw_reverse_register_maa_handler(&when);

	CHECK_FCT(fd_disp_register(rgw_reverse_handle_maa, DISP_HOW_CC,
							   &when, NULL, &maa_handler_hdl));
	*/

	LOG_N("Reverse gateway initialized successfully");
	return 0;
}

/* Response data structure for curl callback */
struct curl_response_data {
	char *data;
	size_t size;
};

/* Curl write callback for response data */
static size_t rgw_curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct curl_response_data *mem = (struct curl_response_data *)userp;
	
	char *ptr = realloc(mem->data, mem->size + realsize + 1);
	if (!ptr) {
		TRACE_ERROR("Not enough memory for curl response");
		return 0;
	}
	
	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;
	
	return realsize;
}

/* HTTP POST helper function using curl */
static int rgw_reverse_http_post(const char *url, const char *json_data, char **response) {
	CURL *curl;
	CURLcode res;
	struct curl_response_data response_data = {NULL, 0};
	
	curl = curl_easy_init();
	if (!curl) {
		TRACE_ERROR("Failed to initialize curl");
		return -1;
	}
	
	/* Set URL */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	
	/* Set POST data */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
	
	/* Set content type to JSON */
	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	/* Set write callback */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rgw_curl_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response_data);
	
	/* Set timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
	
	/* Perform the request */
	res = curl_easy_perform(curl);
	
	/* Check for errors */
	if (res != CURLE_OK) {
		TRACE_ERROR("curl_easy_perform() failed: %s", curl_easy_strerror(res));
		free(response_data.data);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return -1;
	}
	
	/* Get HTTP response code */
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	
	if (g_config && g_config->debug) {
		TRACE_DEBUG(FULL, "HTTP POST to %s returned code %ld", url, http_code);
		if (response_data.data) {
			TRACE_DEBUG(FULL, "Response: %s", response_data.data);
		}
	}
	
	/* Clean up */
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	
	/* Return response if requested */
	if (response) {
		*response = response_data.data;
	} else {
		free(response_data.data);
	}
	
	return (http_code == 200) ? 0 : -1;
}

/* Example usage: Send authentication event to external service */
static void rgw_reverse_notify_auth_event(const char *session_id, const char *event_type, int result) {
	char json_buffer[1024];
	char *response = NULL;
	
	/* Build JSON payload */
	snprintf(json_buffer, sizeof(json_buffer),
		"{\"session_id\":\"%s\",\"event\":\"%s\",\"result\":%d,\"timestamp\":%ld}",
		session_id, event_type, result, time(NULL));
	
	/* Send notification (example URL - would be configurable) */
	const char *notify_url = "http://localhost:8080/api/auth/notify";
	
	if (rgw_reverse_http_post(notify_url, json_buffer, &response) == 0) {
		if (g_config && g_config->debug) {
			TRACE_DEBUG(FULL, "Successfully sent auth event notification");
		}
		free(response);
	} else {
		TRACE_DEBUG(INFO, "Failed to send auth event notification");
	}
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