#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "der_handler.h"
#include "log_utils.h"
#include "utils.h"
#include "process_maa.h"
#include "process_saa.h"

#include <stdbool.h>
#include "eap_aka.h"
#include "sip_auth.h"
#include "rest_api.h"

static int get_imsi_from_der(struct msg **msg, struct avp *avp, char** imsi) {
	struct msg *der = *msg;
	struct avp_hdr *hdr;
	struct avp *avp_local;
	char *user_name = NULL;
	char* temp;

	*imsi = NULL;
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp_local, NULL));
	while (avp_local) {
		CHECK_FCT(fd_msg_avp_hdr(avp_local, &hdr));

		if (hdr->avp_code == 1) {  /* User-Name */
			user_name = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
			CHECK_FCT(vowifi_substring(user_name, 0, '@', &temp));
			CHECK_FCT(vowifi_ltrim_zeros(temp, imsi));
			break;
		}
		CHECK_FCT(fd_msg_browse(avp_local, MSG_BRW_NEXT, &avp_local, NULL));
	}
	return 0;
}

int createDeaFromDer(struct msg *der, struct msg **dea, char* result_message) {
	struct msg *ans;
	//char* result_message;

	/* Create Diameter answer */
	CHECK_FCT(
		fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, 0)
	);
	ans = der;

	//result_message = "DIAMETER_SUCCESS";
	if (result_message != NULL) {
		fd_msg_rescode_set( ans, result_message, NULL, NULL, 1 );
	}
	
	*dea = ans;
	return 0;
}

static int createDeaFromDerAndLdapResponse(struct msg *der, VowifiLdapRestResponse* response, struct msg **dea) {
	struct msg *ans;
	char* result_message;

	/* Create Diameter answer */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &der, 0));
	ans = der;

	switch (response->resultCode) {
		case 1:
			result_message = "DIAMETER_SUCCESS";
			break;
		default:
			result_message = "DIAMETER_AUTHENTICATION_REJECTED";

			//TODO  result-code DIAMETER SUCCES de kell bele experimental-Result-Code
			//Experimental-Result-Code(298) bele kell tenni a visszamenő DEA üzenetbe és beállítani: DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION
			
			/*
			// Add Experimental-Result for VoWiFi rejection /
			struct avp *exp_result, *exp_result_code, *vendor_id;
			union avp_value val;
			struct dict_object *exp_result_dict = NULL, *exp_result_code_dict = NULL, *vendor_id_dict = NULL;
			
			// Find Experimental-Result in dictionary /
			CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Experimental-Result", &exp_result_dict, ENOENT));
			CHECK_FCT(fd_msg_avp_new(exp_result_dict, 0, &exp_result));
			
			// Find Experimental-Result-Code in dictionary /
			CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Experimental-Result-Code", &exp_result_code_dict, ENOENT));
			CHECK_FCT(fd_msg_avp_new(exp_result_code_dict, 0, &exp_result_code));
			val.u32 = 5450;  // DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION 
			CHECK_FCT(fd_msg_avp_setvalue(exp_result_code, &val));
			CHECK_FCT(fd_msg_avp_add(exp_result, MSG_BRW_LAST_CHILD, exp_result_code));
			
			// Find Vendor-Id in dictionary /
			CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Vendor-Id", &vendor_id_dict, ENOENT));
			CHECK_FCT(fd_msg_avp_new(vendor_id_dict, 0, &vendor_id));
			val.u32 = 10415;  // 3GPP Vendor ID /
			CHECK_FCT(fd_msg_avp_setvalue(vendor_id, &val));
			CHECK_FCT(fd_msg_avp_add(exp_result, MSG_BRW_LAST_CHILD, vendor_id));
			
			// Add Experimental-Result to the message //
			CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, exp_result));
			*/
	}
	fd_msg_rescode_set( ans, result_message, NULL, NULL, 1 );
	
	*dea = ans;
	return 0;
}

int fillSessionStateEapPayload(struct sess_state *state, uint8_t* derEapPayload, size_t len) {
	//CHECK_PARAMS(state); // uj state lesz
	state->eapPayload = derEapPayload;
	state->eapPayloadLen = len;
	return 0;
}

bool isAkaChallengeResponse(struct msg *der, struct sess_state **state) {
	uint8_t *eapPayload;
	size_t eapPayloadLen;
	bool isAkaChallenge = false;

	// TODO CHECK_FCT
	getBytesFromMessageWithLengthByAvpCode(der, 462, &eapPayload, &eapPayloadLen);  // EAP-Payload

	if (eapPayloadLen >= 6) {
		// (Response, type: EAP-AKA, subtype: AKA-Challenge)
		if (eapPayload[0] == 0x02 && eapPayload[4] == 0x17 && eapPayload[5] == 0x01) { 
			isAkaChallenge = true;
			FREE(eapPayload);
		} else {
			allocAndInitState(state);
			fillSessionStateEapPayload(*state, eapPayload, eapPayloadLen);
			// itt nem kell free, a session megszuntetesekor fogjuk felszabaditani
		}
	}
	return isAkaChallenge;
}

int getClientAkaChallengeFromDer(struct msg *der, struct sess_state *state) {

	struct avp *payload = NULL;
	getAvpFromMessage(der, 462,  &payload);
	// EAP-Payload

	//getBytesFromMessageByAvpCode(der, 462, &state->eapPayload2, &state->eapPayloadLen2);  // EAP-Payload
	getBytesFromAvpWithLength(payload, &state->eapPayload2, &state->eapPayloadLen2);

	// Debug: print EAP payload as hex string
	if (state->eapPayload2 && state->eapPayloadLen2 > 0) {
		// Allocate memory for hex string (2 chars per byte + null terminator)
		state->eapPayload2Hex = malloc(state->eapPayloadLen2 * 2 + 1);
		if (state->eapPayload2Hex) {
			// Convert to hex string
			for (size_t i = 0; i < state->eapPayloadLen2; i++) {
				sprintf(state->eapPayload2Hex + i * 2, "%02x", state->eapPayload2[i]);
			}
			state->eapPayload2Hex[state->eapPayloadLen2 * 2] = '\0'; // Null terminate
			
			
		} 
	}

	//char* payload_hex_str = state->eapPayload2Hex;
	uint8_t payload_bytes[256];
    size_t payload_len = hex_string_to_bytes(state->eapPayload2Hex, payload_bytes, sizeof(payload_bytes));
	EapAkaAttributes extracted_attrs;
    int found = parse_eap_payload(payload_bytes, payload_len, &extracted_attrs);

	if (found & 0x01) { // AT_RES found
		//memcpy(state->c_res, extracted_attrs.res, extracted_attrs.res_len);
		state->c_res = extracted_attrs.res; 
		state->c_resLen = extracted_attrs.res_len;
		//print_hex("Found AT_res:      ", extracted_attrs.res, extracted_attrs.res_len);
	}
	if (found & 0x02) { // AT_CHECKCODE found
		state->c_checkcode = extracted_attrs.checkcode;
		state->c_checkcodeLen = extracted_attrs.checkcode_len;
	}
	if (found & 0x04) { // AT_MAC found	
		state->c_mac = extracted_attrs.mac;
		state->c_macLen = extracted_attrs.mac_len;
	}

	



/*
	getBytesFromAvpWithLength(c_res, &state->c_res, &state->c_resLen);
	getBytesFromAvpWithLength(c_checkcode, &state->c_checkcode, &state->c_checkcodeLen);
	getBytesFromAvpWithLength(c_mac, &state->c_mac, &state->c_macLen);
*/
	

	return 0;
}

static int processAkaChallenge(struct msg **msg, char* imsi, struct sess_state * state) {
	struct msg *der = *msg;

	getClientAkaChallengeFromDer(der, state);

	if (verifyEapAkaResponse(state) != 0) {
		printf("EAP-AKA Response verification failed.\n");
		*msg = NULL; // Message not processed further
		return -1;
	}
	sendServerAssignmentRequest(msg, imsi, SAT_REGISTRATION);
	
	*msg = NULL; // SAR Message sent (with callback), avoid further processing here
	return 0;
}

static int createErrorReponse(struct msg **msg, enum disp_action *act) {
	struct msg *der = *msg;
	struct msg *dea = NULL;

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

int vowifi_handle_der(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act)
{
	struct msg *der = *msg;
	struct msg *dea = NULL;
	char *imsi = NULL;
	VowifiLdapRestResponse ldapResponse;

	debugPrintMsg(der);

	struct session * session; 
	struct sess_state * state;
	getOrCreateSessionState(der, &session, &state); // TODO free a hook-ban, amikor megszunik a session
	
	TRACE_DEBUG(FULL, "Handling Diameter DER message");

	CHECK_FCT(get_imsi_from_der(msg, avp, &imsi)); 

	

	if (imsi != NULL) {
		if (isAkaChallengeResponse(der, &state)) {
			TRACE_DEBUG(FULL, "DER contains AKA challenge");
			CHECK_FCT(processAkaChallenge(msg, imsi, state));
			// Session TODO storeState(session, state);
			*act = DISP_ACT_CONT;
			return 0;
		} else {
			storeState(session, state);
			call_vowifi_ldap_rest_api(imsi, &ldapResponse);

			if (ldapResponse.resultCode == 1) {
				//logSessionWithPlsql( der, &ldapResponse);
				printf("%s has VoWifi access, accepting request\n", imsi);
				char* sessionId;
				CHECK_FCT(getSessionIdFromMsg(der, &sessionId));
				//logRejectWithPlsql(sessionId,  imsi, der);
				sendMultimediaAuthRequest(der, imsi);
				*act = DISP_ACT_CONT;
				*msg = NULL; // Message forwarded, avoid further processing
				return 0;
			} else {
				char* sessionId;
				CHECK_FCT(getSessionIdFromMsg(der, &sessionId));
				//CHECK_FCT(logRejectedSession(sessionId, imsi, der));
				logRejectWithPlsql(sessionId,  imsi, der);

				//log
        		printf("%s imsi has no VoWifi access, rejecting request\n", imsi);

				//logSessionWithPlsql( der, &ldapResponse);
				CHECK_FCT(createDeaFromDerAndLdapResponse(der, &ldapResponse, &dea));
				if (dea != NULL) {
					/* Send DEA */
					*msg = dea;
					CHECK_FCT(fd_msg_send(msg, NULL, NULL));

					debugPrintMsg(dea);

					*act = DISP_ACT_SEND;
					return 0;
				}
			}
		}
	}

	/* Create error response, a tobbi esetben mar volt return, ide mar csak a hiba jut el*/
	return createErrorReponse(msg, act);
}
