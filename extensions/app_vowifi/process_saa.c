#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "process_saa.h"
#include "log_utils.h"
#include "utils.h"
#include <stdbool.h>

typedef struct {
    struct msg *der;
    int serverAssignmentType;
} CallbackParams;

int sendDeaFromDer(struct msg *der, struct msg *saa) {
    if (der != NULL) {
        struct msg *dea;
        createDeaFromDer(der, &dea, "DIAMETER_SUCCESS");
        addExperimentalResultCode(dea, 10415, 298, 5451); // 3GPP, DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION
        // TODO rekurziv NON-3GPPP-USER-DATA masolas
        //addAvpFromMessageByAvpCode(dea, saa, 1500); // NON-3GPP-USER-DATA
        debugPrintMsg(dea);
        fd_msg_send(&dea, NULL, NULL);
    }
    return 0;
}

int sendServerAssignmentDeregistrationRequest(struct msg **msg, struct msg *der);

void cbSarResponseHandler(void * data, struct msg ** msg) {
    //struct msg *dea = NULL;
	struct msg *saa = *msg;
	//bool ok = true;
	LOG_N("Received SAA reponse\n");
	debugPrintMsg(*msg);

    CallbackParams *cbp = (CallbackParams*)data;

    if (cbp->serverAssignmentType == SAT_USER_DEREGISTRATION) {
        sendDeaFromDer(cbp->der, *msg);
    } else {

        uint32_t apnAccess;
        getChildIntValueFromMessage(saa, 1500, 1502, &apnAccess); // Non-3GPP-User-Data, Non-3GPP-IP-ACCESS-APN

        // TODO valos vizsgalat, mikor nincs apn subscription?
        if (true) { // teszthez
            sendServerAssignmentDeregistrationRequest(msg, cbp->der);
        } else {
            // TODO tobbi eset (van apn subscr)
        }
    }

    *msg = NULL;
}

static int createCallbackParams(struct msg *der, int sat, CallbackParams **cbp) {
    // TODO free a callbackben
    CallbackParams *cbpp = malloc(sizeof(CallbackParams));
    cbpp->der = der;
    cbpp->serverAssignmentType = sat;
    *cbp = cbpp;
    return 0;
}

static int sendServerAssignmentRegistrationRequest(struct msg **msg, char* imsi) {
	struct msg *der = *msg;
	struct msg *sar = NULL;
	struct session *sess = NULL; 

	// TODO minden CHECK_FCT
	createMessageBase(16777265, 301, &sar); // SWx application (16777265), SAR command (301)
	createNewSession(sar, &sess);

	addVendorSpecificApplicationId(sar, 10415, 258);
	addAvpStr(sar, dict_objs.User_Name, (uint8_t*)imsi);
	
	fd_msg_add_origin(sar, 0); // Origin-*AVPs

	addAvpStr(sar, dict_objs.Destination_Realm, vowifiConfig.hssRealm);	
	addAvpStr(sar, dict_objs.Destination_Host, vowifiConfig.hssHost);

	addAvpInt32(sar, dict_objs.Auth_Session_State, 1); // Auth-Session-State (1 = NO_STATE_MAINTAINED)

    addAvpInt32ByAvpCode(sar, 614, 1); // Server-Assignment-Type: Registration

	printf("Generated SAR message for IMSI: %s\n", imsi);
	debugPrintMsg(sar);
	
    
    CallbackParams *cbp = NULL;
    createCallbackParams(der, 1, &cbp);
	fd_msg_send(&sar, cbSarResponseHandler, cbp);
	
	TRACE_DEBUG(FULL, "SAR message sent to HSS");

	return 0;
}

int sendServerAssignmentDeregistrationRequest(struct msg **msg, struct msg *der) {
    char* imsi;
	//struct msg *der = *msg;
	struct msg *sar = NULL;
	struct session *sess = NULL; 

    getStringFromMsg(sar, &imsi, 1); // User-Name

	// TODO minden CHECK_FCT, de az imsi-t fel kell szabaditani
	createMessageBase(16777265, 301, &sar); // SWx application (16777265), SAR command (301)
	createNewSession(sar, &sess);

	addVendorSpecificApplicationId(sar, 10415, 258);
	addAvpStr(sar, dict_objs.User_Name, (uint8_t*)imsi);
	
	fd_msg_add_origin(sar, 0); // Origin-*AVPs

	addAvpStr(sar, dict_objs.Destination_Realm, vowifiConfig.hssRealm);	
	addAvpStr(sar, dict_objs.Destination_Host, vowifiConfig.hssHost);

	addAvpInt32(sar, dict_objs.Auth_Session_State, 1); // Auth-Session-State (1 = NO_STATE_MAINTAINED)

    addAvpInt32ByAvpCode(sar, 614, 5); // Server-Assignment-Type: User-Deregistration

	printf("Generated SAR message for IMSI: %s\n", imsi);
	debugPrintMsg(sar);
	
    CallbackParams *cbp = NULL;
    createCallbackParams(der, 5, &cbp);
	fd_msg_send(&sar, cbSarResponseHandler, cbp);
	
	TRACE_DEBUG(FULL, "SAR message sent to HSS");

    FREE(imsi);
	return 0;
}

int sendServerAssignmentRequest(struct msg **msg, char* imsi, int sat) {
    switch (sat) {
        case SAT_REGISTRATION: 
            return sendServerAssignmentRegistrationRequest(msg, imsi);
        /* Nem varunk ilyet, a lancban (SAR->SAA-> kozvetlenul hivjuk a registration-bol )
        case SAT_USER_DEREGISTRATION:
            return sendServerAssignmentDeregistrationRequest(msg, imsi);
            */
        default:
            return -1;
    }    
}
