#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "process_maa.h"
#include "log_utils.h"
#include "utils.h"
#include <stdbool.h>
#include "eap_aka.h"
#include "sip_auth.h"
#include "rest_api.h"
#include "der_handler.h"

static int fillDeaWithFailure(struct msg *dea, struct msg *maa) {
	addAvpFromMessageByAvpCode(maa, dea, 297); // Experimental-Result
	uint32_t experimentalResultCode;
	uint32_t vendorId;

	if (getChildIntValueFromMessage(maa, 297, 298, &experimentalResultCode) == 0) { // Experimental-Result-Code
		if (getChildIntValueFromMessage(maa, 297, 266, &vendorId) == 0) { // Vendor-Id
			addExperimentalResultCode(dea, vendorId, 297, experimentalResultCode);
		}
	}
	u_int8_t eapFailure[3] = {0x04, 0x01, 0x04}; // EAP Failure packet
	addAvpBytes(dea, dict_objs.EAP_Payload, eapFailure, 3);
	return 0;
}

static int fillDeaWithSuccess(struct msg *der, struct msg *dea, struct msg *maa) {
	fd_msg_rescode_set(dea, "DIAMETER_MULTI_ROUND_AUTH", NULL, NULL, 1 );

	char* eapAkaChallenge = NULL;
	size_t eapAkaChallengeLen = 0;

	// TODO CHECK_FCT minden esetben
	struct avp *sipAuthenticate = NULL;
	getAvpChildFromMessage(maa, 612, 609, &sipAuthenticate); 

	struct avp *sipAuthorization = NULL;
	getAvpChildFromMessage(maa, 612, 610, &sipAuthorization);
	
	struct avp *confidentialityKey = NULL;
	getAvpChildFromMessage(maa, 612, 625, &confidentialityKey);

	struct avp *integrityKey = NULL;
	getAvpChildFromMessage(maa, 612, 626, &integrityKey);

	// TODO get RAND, AUTN, CK, IK from MAA message
	// for testing, hardcoded values are used
	
	//const char* randHex = "1b203be67c09ce0e94c263979c61284f";
	//const char* autnHex = "97a0e842aa8a0001e06d3125b442a7e9";
	//const char* ckHex = "ffa8c96750a95886de3ff78b1d55abe6";
	//const char* ikHex = "c475b7976d6929e85bf26888344c9769";
	
	//char* randHex = "1b203be67c09ce0e94c263979c61284f";
	//char* autnHex = "97a0e842aa8a0001e06d3125b442a7e9";

	char* randHex = NULL;
	char* autnHex = NULL;
	// TODO megkeresni a free helyet, felszabaditani, ha mar nem kell
	generateAtRandAtAutn(&randHex, &autnHex);

	const char* ckHex = NULL;
	getBytesFromAvp(confidentialityKey, (uint8_t**)&ckHex);

	const char* ikHex = NULL;
	getBytesFromAvp(integrityKey, (uint8_t**)&ikHex);
	
	char* identity = NULL;
	getStringFromMsg(der, &identity, 1); // User-Name
	generateEapAkaChallenge(identity, randHex, autnHex, ckHex, ikHex, (unsigned char**)&eapAkaChallenge, &eapAkaChallengeLen);

	addAvpBytes(dea, dict_objs.EAP_Payload, (uint8_t*)eapAkaChallenge, eapAkaChallengeLen);

	// TODO adatok mentese a session-be, ha kell egyeb adatok tarolni, akkor a sess_state struktura modosithato
	struct session * session;
	struct sess_state * state;
	getOrCreateSessionState(der, &session, &state);
	
	//state->identity vizsgálata ha nincs kitöltve feltöltjök
	if (!state->identity) {
		state->identity = identity;
	}
	//imsi beallitasa
	if (!state->imsi) {
		char* imsi = NULL;
		getStringFromMsg(der, &imsi, 1); // User-Name
		// Extract IMSI from identity (before '@' character)
		char* at_pos = strchr(imsi, '@');
		if (at_pos) {
			*at_pos = '\0'; // Truncate at '@'
		}
		state->imsi = imsi;	
	}

	
	if(!state->serviceSelection){
		char* serviceSelection = NULL;
		getStringFromMsg(der, &serviceSelection, 493);
		state->serviceSelection = serviceSelection; 
	} 

	// xres beállítása a SIP-Authorization AVP-ből
	getBytesFromAvpWithLength(sipAuthorization, &state->xres, &state->xresLen);
	getBytesFromAvpWithLength(confidentialityKey, &state->ck, &state->ckLen);
	getBytesFromAvpWithLength(integrityKey, &state->ik, &state->ikLen);
	// RAND és AUTN beállítása a SIP-Authenticate AVP-ből
	
	//getBytesFromAvpWithLength(randHex, &state->rand, &state->randLen);
	//getBytesFromAvpWithLength(autnHex, &state->autn, &state->autnLen);
	
	//hexStringToBytes(randHex, &state->rand, &state->randLen);
	//hexStringToBytes(autnHex, &state->autn, &state->autnLen);
	state->autn = autnHex;
	state->autnLen = strlen(autnHex);

	state->rand = randHex;
	state->randLen = strlen(randHex);
	
	storeState(session, state);
	return 0;
}

static void hexStringToBytes(const char* hexStr, uint8_t** bytes, size_t* len) {
    if (!hexStr) return;
    
    *len = strlen(hexStr) / 2;
    *bytes = malloc(*len);
    
    for (size_t i = 0; i < *len; i++) {
        sscanf(hexStr + 2*i, "%2hhx", &(*bytes)[i]);
    }
}

// TODO session MAA
void cbMarResponseHandler(void * data, struct msg ** msg) {
	struct msg *dea = NULL;
	struct msg *maa = *msg;
	bool ok = true;
	printf("Received MAA reponse\n");
	debugPrintMsg(*msg);
	struct msg *der = (struct msg*)data;	
	createDeaFromDer(der, &dea, NULL);
	if (dea != NULL) {
		fd_msg_add_origin(dea, 0); // Origin-*AVPs
		int avpCodesToCopyFromMAA[] = {1}; // User-Name
		addAvpFromMessageByAvpCodeArray(maa, dea, avpCodesToCopyFromMAA, 1);
		int avpCodesToCopyFromDER[] = {274, 258}; // Auth-Request-Type, Auth-Application-Id
		addAvpFromMessageByAvpCodeArray(der, dea, avpCodesToCopyFromDER, 2);

		uint32_t resultCode;
		getResultCodeFromMessage(maa, &resultCode);
		if (resultCode == 2001) { // DIAMETER_SUCCESS
			if (fillDeaWithSuccess(der, dea, maa) != 0) {
				ok = false;
			}
		}
		if (!ok){
			if (fillDeaWithFailure(dea, maa) != 0) {
				ok = false;
			}	
		}
		
		/* Send DEA */
		*msg = dea;
		debugPrintMsg(dea);
		if (ok == true) {
			fd_msg_send(msg, NULL, NULL);
		}
	}
}

int sendMultimediaAuthRequest(struct msg *der, char* imsi) {
	struct msg *mar = NULL;
	struct session *sess = NULL; 

	// TODO minden CHECK_FCT
	createMessageBase(16777265, 303, &mar); // SWx application (16777265), MAR command (303)

	// pcap-ban mas session_id latszik, lehet, hogy generalni kell 
	createNewSession(mar, &sess);
	
	addAvpInt32(mar, dict_objs.Auth_Application_Id, 16777265); // Auth-Application-Id (SWx = 16777265)

	fd_msg_add_origin(mar, 0); // Origin-*AVPs

	addAvpStr(mar, dict_objs.Destination_Realm, vowifiConfig.hssRealm);	
	addAvpStr(mar, dict_objs.Destination_Host, vowifiConfig.hssHost);


	addAvpStr(mar, dict_objs.User_Name, (uint8_t*)imsi);

	addAvpInt32(mar, dict_objs.Auth_Session_State, 1); // Auth-Session-State (1 = NO_STATE_MAINTAINED)

	addSipAuth(mar);
	
	printf("Generated MAR message for IMSI: %s\n", imsi);
	debugPrintMsg(mar);
	
	// Send MAR message to HSS
	CHECK_FCT(fd_msg_send(&mar, cbMarResponseHandler, der));
	
	TRACE_DEBUG(FULL, "MAR message sent to HSS");
	
	return 0;
}