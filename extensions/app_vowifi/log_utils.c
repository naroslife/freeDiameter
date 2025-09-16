#include <freeDiameter/extension.h>
#include <time.h>
#include "vowifi.h"
#include "log_utils.h"
#include "der_handler.h"
#include "utils.h"
#include "test_pool.h"

//TODO adatbázis oracle log
int logRejectedSession(const char* sessionId, const char* imsi, struct msg* der) {
	struct avp *avp;
	struct avp_hdr *hdr;

	//local variables
	char *user_name = NULL;
	int exp_res_code = 0;
	char *origin_host = NULL;

	/* Extract AVPs from Diameter message */
	CHECK_FCT(fd_msg_browse(der, MSG_BRW_FIRST_CHILD, &avp, NULL));
	while (avp) {
		CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
		
		if (hdr->avp_code == 1) {  /* User-Name */
			user_name = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		else if (hdr->avp_code == 298) {  /* Experimental-Result-Code */
			exp_res_code = hdr->avp_value->i32;
		} else if (hdr->avp_code == 264) {  /* Origin-Host */
			origin_host = strndup((char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
		}
		
		CHECK_FCT(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL));
	}

	// Set default values for NULL variables
	if (!user_name) user_name = strdup("unknown-user");
	if (!origin_host) origin_host = strdup("unknown-host");
	if (exp_res_code == 0) exp_res_code = 5012; // Default experimental result code for auth failure

	int insert_result = oracle_insert_rejected_logon(
			sessionId ? sessionId : "unknown-session",              // session_id (unique)
			user_name,             // user_name
			exp_res_code,          // exp_res_code (initial: auth failure)
			origin_host,           // origin_host
			//TODO TIMESTAMP       // log_time (current timestamp)
			vowifiConfig.car_server_ip      // car_server_ip
		);

	printf("Rejected session log: session_id=%s, imsi=%s, user_name=%s, origin_host=%s, exp_res_code=%d\n", 
		sessionId ? sessionId : "unknown-session", 
		imsi ? imsi : "N/A",
		user_name,
		origin_host,
		exp_res_code);

	free(user_name);
	free(origin_host);	
	return 0;
}

int logRejectWithPlsql( char* sessionId,  char* imsi, struct msg* der) {


	// Test parameters
     //char *msg = "johndoe|EXP123|host01|ABC123|20250912103045";
	 char msg[4000] = {0};
     char *delim = "|";
    int64_t rc = 0;
    char rm[4000] = {0};

	/*
	char * msg = NULL;
	char * username = NULL;
	char * exp_code_str = vowifiConfig.exp_Res_code_ldap_missing;
	char * origin_host = NULL;
	uint32_t exp_res_code = 0;
	*/
	/*
	// Extract string values from DER message
	int username_result = getStringFromMsg(der, &username, 1);         // User-Name
	int origin_host_result = getStringFromMsg(der, &origin_host, 264);    // Origin-Host
	
	// Extract experimental result code as integer
	int exp_code_result = getIntValueFromMessage(der, 298, &exp_res_code);    // Experimental-Result-Code
	
	printf("Debug: AVP extraction results:\n");
	printf("  Username (AVP 1): %s (result: %d)\n", username ? username : "NULL", username_result);
	printf("  Origin-Host (AVP 264): %s (result: %d)\n", origin_host ? origin_host : "NULL", origin_host_result);
	printf("  Exp-Result-Code (AVP 298): %u (result: %d)\n", exp_res_code, exp_code_result);
	
	// Set default values for NULL variables
	if (!username) username = strdup("unknown-user");
	if (!origin_host) origin_host = strdup("unknown-host");
	if (exp_res_code == 0) exp_res_code = 5012; // Default auth failure code
	
	// Convert exp_res_code to string
	exp_code_str = malloc(16);
	if (exp_code_str) {
		snprintf(exp_code_str, 16, "%u", exp_res_code);
	} else {
		exp_code_str = vowifiConfig.exp_Res_code_ldap_missing;//strdup("5012");
	}
		*/

	// Build the message string: username|exp_code|origin_host|session_id|timestamp
	char* session = sessionId ? sessionId : "unknown-session";
	//char * origin_host = getStringFromMsg(der, 264);    // Origin-Host

	
	if (msg) {
		// Get current timestamp
		time_t now = time(NULL);
		struct tm *tm_info = localtime(&now);
		char timestamp[20];
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
		
		sprintf(msg,  "%s|%s|%s|%s|%s\0", imsi, vowifiConfig.exp_Res_code_ldap_missing, vowifiConfig.origin_host, session, timestamp);
	} 

    printf("\nCalling oracle_rejected_logon_procedureCall with:\n");
    printf("  Message: %s\n", msg);
    printf("  Delimiter: %s\n", delim);
    
    // Call the procedure
    if (oracle_rejected_logon_procedureCall(msg, delim, &rc, rm, sizeof(rm))) {
        printf("\n✅ Procedure call successful!\n");
        printf("  Return Code: %ld\n", (long)rc);
       // printf("  Return Message: %s\n", strlen(rm) > 0 ? rm : "<empty>");
    } else {
        printf("\n❌ Procedure call failed!\n");
    }
    
    // Free allocated memory
    
	//TODO PL/SQL procedure call to log rejected session
	return 0;
}

int logSessionWithPlsql(struct msg *der, VowifiLdapRestResponse* response){
	/*
	char *session_id = NULL;
	char *user_name = NULL;
	char *origin_host = NULL;
	char *origin_realm = NULL;
	char *calling_station_id = NULL;
	char *framed_ip_address = NULL;
	char *service_selection = NULL;
	uint32_t origin_state_id = 0;
	uint32_t auth_request_type = 0;
	char *msisdn = NULL; 
	char *termination_cause = "999";
	
	char active = 'Y';  // char típus egyetlen karakter
	getStringFromMsg(der, &session_id, 263);     // Session-Id
	getStringFromMsg(der, &user_name, 1);         // User-Name
	getStringFromMsg(der, &origin_host, 264);    // Origin-Host
	getStringFromMsg(der, &origin_realm, 296);   // Origin-Realm
	getStringFromMsg(der, &calling_station_id, 31); // Calling-Station-Id
	getStringFromMsg(der, &framed_ip_address, 8); // Framed-IP-Address
	getStringFromMsg(der, &service_selection, 493); // Service-Selection
	getIntValueFromMessage(der, 278, &origin_state_id); // Origin-State-Id
	getIntValueFromMessage(der, 274, &auth_request_type); // Auth-Request-Type
	getStringFromMsg(der, &msisdn, 1); // MSISDN
	
	// Convert uint32_t to string for auth_request_type
	char auth_request_type_str[16];
	snprintf(auth_request_type_str, sizeof(auth_request_type_str), "%u", auth_request_type);
	*/


	/*
	int64_t cmd_code = 1;
     char *session_id = "SES123456789";
     char *user_name = "johndoe@example.com";
    int64_t origin_state_id = 100;
     char *auth_request_type = "AUTHORIZE_AUTHENTICATE"; // String érték
     char *calling_station_id = "00:11:22:33:44:55";
     char *ip_address = "192.168.1.100";
     char *msisdn = "+36301234567";
     char *service_selection = "internet";
     char *termination_cause = "LOGOUT";
     char *in_pass = "secret123";
    char password_out[100] = {0};
    */

		int64_t cmd_code = 0;
     char *session_id = NULL;
     char *user_name = NULL;
     char *origin_state_id = NULL;
     char *auth_request_type = NULL; // String érték
     char *calling_station_id = NULL;
     char *ip_address = NULL;
     char *msisdn = NULL;
     char *service_selection = NULL;
     char *termination_cause = NULL;
     char *in_pass = NULL;
    char password_out[100] = {0};

	// Extract command code from message header
	struct msg_hdr *hdr;
	CHECK_FCT(fd_msg_hdr(der, &hdr));
	cmd_code = hdr->msg_code;
	
	getStringFromMsg(der, &session_id, 263);     // Session-Id
	getStringFromMsg(der, &user_name, 1); 
	getStringFromMsg(der, &origin_state_id, 278);    
	getStringFromMsg(der, &auth_request_type, 274);      
 	getStringFromMsg(der, &calling_station_id, 31); // Calling-Station-Id
	getStringFromMsg(der, &ip_address, 2805); // Framed-IP-Address
	getStringFromMsg(der, &msisdn, 1); 
	getStringFromMsg(der, &service_selection, 493); // Service-Selection
	
	// TODO: Extract UE-Local-IP-Address (3GPP vendor AVP 2805)
	// This would require a vendor-specific AVP extraction function
	
	// Extract only the phone number part from MSISDN if it contains @
	if (msisdn && strchr(msisdn, '@')) {
		char *at_pos = strchr(msisdn, '@');
		size_t phone_len = at_pos - msisdn;
		char *phone_only = malloc(phone_len + 1);
		if (phone_only) {
			strncpy(phone_only, msisdn, phone_len);
			phone_only[phone_len] = '\0';
			free(msisdn);
			msisdn = phone_only;
		}
	}
	
	// Set default values for NULL variables
	if (!session_id) session_id = strdup("unknown-session");
	if (!user_name) user_name = strdup("unknown-user");
	if (!origin_state_id) origin_state_id = strdup("0");
	if (!auth_request_type) auth_request_type = strdup("UNKNOWN");
	if (!calling_station_id) calling_station_id = strdup("00:00:00:00:00:00");
	if (!ip_address) ip_address = strdup("0.0.0.0");
	if (!msisdn) msisdn = strdup("36301234567");  // Valid MSISDN format
	if (!service_selection) service_selection = strdup("unknown-service");
	if (!termination_cause) termination_cause = strdup("UNKNOWN");
	if (!in_pass) in_pass = strdup("");

    printf("Parameters:\n");
    printf("  CMD_CODE: %ld\n", (long)cmd_code);
    printf("  SESSION_ID: %s\n", session_id);
    printf("  USER_NAME: %s\n", user_name);
    printf("  ORIGIN_STATE_ID: %ld\n", (long)origin_state_id);
    printf("  AUTH_REQUEST_TYPE: %s\n", auth_request_type);
    printf("  CALLING_STATION_ID: %s\n", calling_station_id);
    printf("  IP_ADDRESS: %s\n", ip_address);
    printf("  MSISDN: %s\n", msisdn);
    printf("  SERVICE_SELECTION: %s\n", service_selection);
    printf("  TERMINATION_CAUSE: %s\n", termination_cause);
    printf("  IN_PASS: %s\n", in_pass);
    
    if (oracle_write_session_data_procedureCall(cmd_code, session_id, user_name,
                                               origin_state_id, auth_request_type,
                                               calling_station_id, ip_address,
                                               msisdn, service_selection,
                                               termination_cause, in_pass,
                                               password_out, sizeof(password_out))) {
        printf("\n✅ Session data procedure call successful!\n");
        printf("  Password OUT: %s\n", strlen(password_out) > 0 ? password_out : "<empty>");
    } else {
        printf("\n❌ Session data procedure call failed!\n");
        printf("  Error: %s\n", oracle_get_last_error());
    }
    
    // Free allocated memory (including default values)
    free(session_id);
    free(user_name);
    free(origin_state_id);
    free(auth_request_type);
    free(calling_station_id);
    free(ip_address);
    free(msisdn);
    free(service_selection);
    free(termination_cause);
    free(in_pass);
    
	return 0;
}                



int createDerSessionLog(struct msg *der, VowifiLdapRestResponse* response){

	//itt fel kelle dolgozni a der üzenetet - használjuk a utils.c segédfüggvényeit
	char *session_id = NULL;
	char *user_name = NULL;
	char *origin_host = NULL;
	char *origin_realm = NULL;
	char *calling_station_id = NULL;
	char *framed_ip_address = NULL;
	char *service_selection = NULL;
	uint32_t origin_state_id = 0;
	uint32_t auth_request_type = 0;
	char *msisdn = NULL; 
	char *termination_cause = "999";
	
	char *active = "Y";  // String típus egyetlen karakter
	getStringFromMsg(der, &session_id, 263);     // Session-Id
	getStringFromMsg(der, &user_name, 1);         // User-Name
	getStringFromMsg(der, &origin_host, 264);    // Origin-Host
	getStringFromMsg(der, &origin_realm, 296);   // Origin-Realm
	getStringFromMsg(der, &calling_station_id, 31); // Calling-Station-Id
	getStringFromMsg(der, &framed_ip_address, 8); // Framed-IP-Address
	getStringFromMsg(der, &service_selection, 493); // Service-Selection
	getIntValueFromMessage(der, 278, &origin_state_id); // Origin-State-Id
	getIntValueFromMessage(der, 274, &auth_request_type); // Auth-Request-Type
	getStringFromMsg(der, &msisdn, 1); // MSISDN
	
	// Extract only the phone number part from MSISDN if it contains @
	if (msisdn && strchr(msisdn, '@')) {
		char *at_pos = strchr(msisdn, '@');
		size_t phone_len = at_pos - msisdn;
		char *phone_only = malloc(phone_len + 1);
		if (phone_only) {
			strncpy(phone_only, msisdn, phone_len);
			phone_only[phone_len] = '\0';
			free(msisdn);
			msisdn = phone_only;
		}
	}
	
	// Set default values for NULL string variables
	if (!session_id) session_id = strdup("unknown-session");
	if (!user_name) user_name = strdup("unknown-user");
	if (!origin_host) origin_host = strdup("unknown-host");
	if (!origin_realm) origin_realm = strdup("unknown-realm");
	if (!calling_station_id) calling_station_id = strdup("00:00:00:00:00:00");
	if (!framed_ip_address) framed_ip_address = strdup("0.0.0.0");
	if (!service_selection) service_selection = strdup("unknown-service");
	if (!msisdn) msisdn = strdup("36301234567");
	
	// Convert uint32_t to string for auth_request_type
	char auth_request_type_str[16];
	snprintf(auth_request_type_str, sizeof(auth_request_type_str), "%u", auth_request_type);

	int session_log_result = oracle_insert_session_log(
			session_id,         // session_id
			user_name,              // user_name
			(double)origin_state_id,                                          // origin_state_id
			auth_request_type_str,                                            // auth_request_type (string)
			calling_station_id,                                              // calling_station_id
			//TODO TIMESTAMP,                                               // log_time (current timestamp)
			framed_ip_address,                                     // ip_address
			msisdn,                                    // msisdn
			active,                                                 // active
			service_selection,                                    // service_selection
			NULL,                                                // start_timestamp (NULL for SYSTIMESTAMP)
			//TODO Stop_Timestamp
			termination_cause, // termination_cause
			vowifiConfig.car_server_ip                                    // car_server_ip
			//TODO Update_count
		);

	if (session_log_result) {
		printf("   ✓ Session log entry inserted successfully\n");
	} else {
		printf("   ! Failed to insert session log entry: %s\n", oracle_get_last_error());
	}
		
	// Free allocated memory
	free(session_id);
	free(user_name);
	free(origin_host);
	free(origin_realm);
	free(calling_station_id);
	free(framed_ip_address);
	free(service_selection);
	free(msisdn);

	return 0;
}