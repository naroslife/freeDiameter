#include <freeDiameter/extension.h>
#include "sip_auth.h"
#include <stdbool.h>

int addSipAuth(struct msg *mar) {
	struct avp *avp;
	union avp_value val;

	// Add SIP-Auth-Data-Item AVP (for EAP-AKA)
	struct dict_object *sip_auth_data_item = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
	                   "SIP-Auth-Data-Item", &sip_auth_data_item, ENOENT) == 0) {
		
		CHECK_FCT(fd_msg_avp_new(sip_auth_data_item, 0, &avp));
		
		// Add SIP-Authentication-Scheme (EAP-AKA = 1)
		struct dict_object *sip_auth_scheme = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "SIP-Authentication-Scheme", &sip_auth_scheme, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_auth_scheme, 0, &scheme_avp));
			val.os.data = (uint8_t*)"EAP-AKA";
			val.os.len = 7;
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}

		struct dict_object *sip_item_number = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "SIP-Item-Number", &sip_item_number, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_item_number, 0, &scheme_avp));
			val.u32 = 1;
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}
		
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	}
	
	// Add SIP-Number-Auth-Items (number of authentication items requested)
	struct dict_object *sip_num_auth_items = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
	                   "SIP-Number-Auth-Items", &sip_num_auth_items, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(sip_num_auth_items, 0, &avp));
		val.u32 = 5;
		CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
		CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
	}
	return 0;
}

int addTestSipAuthData(struct msg *maa, struct msg *mar) {
	struct avp *avp;
	union avp_value val;

	// Add SIP-Auth-Data-Item AVP (for EAP-AKA)
	struct dict_object *sip_auth_data_item = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
	                   "SIP-Auth-Data-Item", &sip_auth_data_item, ENOENT) == 0) {
		
		CHECK_FCT(fd_msg_avp_new(sip_auth_data_item, 0, &avp));
		
		// Add SIP-Authentication-Scheme (EAP-AKA = 1)
		struct dict_object *sip_auth_scheme = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "SIP-Authentication-Scheme", &sip_auth_scheme, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_auth_scheme, 0, &scheme_avp));
			val.os.data = (uint8_t*)"EAP-AKA";
			val.os.len = 7;
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}
		
		CHECK_FCT(fd_msg_avp_add(maa, MSG_BRW_LAST_CHILD, avp));

		struct dict_object *sip_authenticate = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "SIP-Authenticate", &sip_authenticate, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_authenticate, 0, &scheme_avp));
			val.os.data = (uint8_t*)"1b203be67c09ce0e94c263979c61284f97a0e842aa8a0001e06d3125b442a7e9";
			val.os.len = CONSTSTRLEN("1b203be67c09ce0e94c263979c61284f97a0e842aa8a0001e06d3125b442a7e9");
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}

		struct dict_object *sip_authorization = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "SIP-Authorization", &sip_authorization, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_authorization, 0, &scheme_avp));
			val.os.data = (uint8_t*)"57c56f14996876c9";
			val.os.len = CONSTSTRLEN("57c56f14996876c9");
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}
		
		struct dict_object *sip_ck = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "Confidentiality-Key", &sip_ck, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_ck, 0, &scheme_avp));
			val.os.data = (uint8_t*)"ffa8c96750a95886de3ff78b1d55abe6";
			val.os.len = CONSTSTRLEN("ffa8c96750a95886de3ff78b1d55abe6");
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}

		struct dict_object *sip_ik = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS, 
		                   "Integrity-Key", &sip_ik, ENOENT) == 0) {
			struct avp *scheme_avp;
			CHECK_FCT(fd_msg_avp_new(sip_ik, 0, &scheme_avp));
			val.os.data = (uint8_t*)"c475b7976d6929e85bf26888344c9769";
			val.os.len = CONSTSTRLEN("c475b7976d6929e85bf26888344c9769");
			CHECK_FCT(fd_msg_avp_setvalue(scheme_avp, &val));
			CHECK_FCT(fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, scheme_avp));
		}

		//CHECK_FCT(fd_msg_avp_add(maa, MSG_BRW_LAST_CHILD, avp));
        fd_msg_avp_add(maa, MSG_BRW_LAST_CHILD, avp);
	}
	
	// Add SIP-Number-Auth-Items (number of authentication items requested)
	struct dict_object *sip_num_auth_items = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "SIP-Number-Auth-Items", &sip_num_auth_items, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(sip_num_auth_items, 0, &avp));
		val.u32 = 1; // Request 1 authentication vector
		CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
		CHECK_FCT(fd_msg_avp_add(maa, MSG_BRW_LAST_CHILD, avp));
	}
	
	return 0;
}