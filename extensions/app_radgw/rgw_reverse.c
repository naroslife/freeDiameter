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
	LOG_N("REVERSE GATEWAY: Sending RADIUS request to %s:%d (fd=%d, %zu bytes)",
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
	ret = rgw_reverse_radius_send_recv(rad_req, &rad_resp);
	if (ret != 0) {
		TRACE_ERROR("Failed to communicate with RADIUS server");
		goto error;
	}
	
	/* Convert RADIUS response to DEA */
	ret = rgw_reverse_radius_to_dea(rad_resp, der, &dea);
	if (ret != 0) {
		TRACE_ERROR("Failed to convert RADIUS to DEA");
		goto error;
	}
	
	/* Update the message pointer to point to the answer */
	*msg = dea;
	
	/* Send DEA */
	CHECK_FCT(fd_msg_send(msg, NULL, NULL));
	
	/* Cleanup */
	radius_msg_free(rad_req);
	radius_msg_free(rad_resp);
	
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
	
	radius_msg_free(rad_req);
	radius_msg_free(rad_resp);
	
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