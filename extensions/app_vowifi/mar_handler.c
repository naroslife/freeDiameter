#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "mar_handler.h"
#include "log_utils.h"
#include "utils.h"
#include <stdbool.h>
#include "sip_auth.h"

static int fillSuccessTestAnswer(char* imsi, struct msg *mar, struct msg *maa) {
	fd_msg_rescode_set(maa, "DIAMETER_SUCCESS", NULL, NULL, 1 );
	addTestSipAuthData(maa, mar);
	return 0;
}

// Csak teszt, a HSS allitja ossze az eles valtozatban
static int fillTestAnswer(struct msg *mar, struct msg *maa) {
	char* imsi;
	getStringFromMsg(mar, &imsi, 1); // User-Name

	printf("IMSI MAR: %s,", imsi);
	addAvpStr(maa, dict_objs.User_Name, (uint8_t*)imsi);
	addAvpInt32(maa, dict_objs.Auth_Session_State, 1); // Auth-Session-State (1 = NO_STATE_MAINTAINED)
	addAvpStr(maa, dict_objs.Origin_Realm, vowifiConfig.hssRealm);	
	addAvpStr(maa, dict_objs.Origin_Host, vowifiConfig.hssHost);
	addVendorSpecificApplicationId(maa, 10415, 258);

	if (strncmp("910101234", imsi, 9) == 0) {
		printf(" Acepted\n");
		fillSuccessTestAnswer(imsi, mar, maa);
	} else {
		printf(" Rejected\n");
		addExperimentalResultCode(maa, 10415, 297, 5450); // 3GPP, DIAMETER_AUTHENTICATION_REJECTED
	}
	free(imsi);
	return 0;
}

static int createMaaFromMar(struct msg *mar, struct msg **maa) {
	struct msg *ans = mar;

	/* Create Diameter answer */
	CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &ans, 0));

	fillTestAnswer(mar, ans);
	
	*maa = ans;
	return 0;
}

int vowifi_handle_mar(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act) {
	struct msg *mar = *msg;
	struct msg *maa = NULL;									

    TRACE_DEBUG(FULL, "Handling Diameter MAR message");

	debugPrintMsg(mar);

	CHECK_FCT(createMaaFromMar(mar, &maa)); 

	debugPrintMsg(maa);									

	//CHECK_FCT(fd_msg_send(&maa, NULL, NULL));
	
	*msg = maa;
	*act = DISP_ACT_SEND;
	return 0;
}