#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "sar_handler.h"
#include "log_utils.h"
#include "utils.h"
#include <stdbool.h>
#include "sip_auth.h"

static int addNon3GppUserData(struct msg *saa, uint32_t apnAccessCode) {
    struct avp *avp;

    struct dict_object *non3GppUserData = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "Non-3GPP-User-Data", &non3GppUserData, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(non3GppUserData, 0, &avp));

		struct dict_object *apn = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                  	"Non-3GPP-IP-Access-APN", &apn, ENOENT) == 0) {					
			struct avp *apnAvp;
			fd_msg_avp_new(apn, 0, &apnAvp);
			fd_msg_avp_setvalue(apnAvp, &(union avp_value){ .u32 = apnAccessCode });
			fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, apnAvp);
		}

		fd_msg_avp_add(saa, MSG_BRW_LAST_CHILD, avp);
	}
	return 0;
}


// TODO
static int fillSuccessTestAnswer(char* imsi, struct msg *sar, struct msg *saa) {
	return 0;
}

// TODO
static int fillNoApnAnswer(struct msg *sar, struct msg *saa) {
    addNon3GppUserData(saa, 0); // Non-3GPP-IP-Access-APN: NON_3GPP_APNS_ENABLE (0)

	return 0;
}

// Csak teszt, a HSS allitja ossze az eles valtozatban
static int fillTestAnswer(struct msg *sar, struct msg *saa) {
	char* imsi;
	getStringFromMsg(sar, &imsi, 1); // User-Name

	printf("IMSI SAR: %s,", imsi);
	addAvpStr(saa, dict_objs.User_Name, (uint8_t*)imsi);
	addAvpInt32(saa, dict_objs.Auth_Session_State, 1); // Auth-Session-State (1 = NO_STATE_MAINTAINED)
	addAvpStr(saa, dict_objs.Origin_Realm, vowifiConfig.hssRealm);	
	addAvpStr(saa, dict_objs.Origin_Host, vowifiConfig.hssHost);
	addVendorSpecificApplicationId(saa, 10415, 258);
    fd_msg_rescode_set(saa, "DIAMETER_SUCCESS", NULL, NULL, 1 );

    int serverAssignmentType = -1;
    getIntValueFromMessage(sar, 614, (uint32_t*)&serverAssignmentType); // Server-Assignment-Type
    switch (serverAssignmentType) {
        case 1: // User-Registration
            if (strncmp("810101234", imsi, 9) == 0) {
                printf(" Acepted\n");
                fillSuccessTestAnswer(imsi, sar, saa);
            } else {
                printf(" Rejected\n");
                fillNoApnAnswer(sar, saa);
            }
            break;
        case 5: // User-Deregistration
            // Nem kell semmi, mar minden adat betoltve
            break;
    }
	
	free(imsi);
	return 0;
}

static int createSaaFromSar(struct msg *sar, struct msg **saa) {
	struct msg *ans = sar;

	/* Create Diameter answer */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &ans, 0));

	fillTestAnswer(sar, ans);
	
	*saa = ans;
	return 0;
}

int vowifi_handle_sar(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act) {
	struct msg *sar = *msg;
	struct msg *saa = NULL;									

    TRACE_DEBUG(FULL, "Handling Diameter SAR message");

	debugPrintMsg(sar);

	CHECK_FCT(createSaaFromSar(sar, &saa)); 

	debugPrintMsg(saa);									

	//CHECK_FCT(fd_msg_send(&saa, NULL, NULL));
	
	*msg = saa;
	*act = DISP_ACT_SEND;
	return 0;
}