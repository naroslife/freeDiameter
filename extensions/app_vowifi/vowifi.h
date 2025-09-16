#ifndef __VOWIFI_H__ 
#define __VOWIFI_H__

#include <freeDiameter/extension.h>

#define FREE(p) { if (p) { free(p); p = NULL; } }

/* Dictionary objects */
typedef struct {
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
	struct dict_object *Destination_Host;
	struct dict_object *SIP_Auth_Data_Item;
	struct dict_object *SIP_Authentication_Scheme;
	struct dict_object *SIP_Number_Auth_Items;
	struct dict_object *Server_Name;
} DICT_OBJS;

typedef struct {
	uint8_t* hssHost;
	uint8_t* hssRealm;
	uint8_t* ldapRestUrl;
	os0_t sessionIdSuffix;
	size_t sessionIdSuffixLen;
	char* db_user;
	char* db_pass;
	char* db_conn;
	int db_minSessions;
	int db_maxSessions;
	int db_sessionIncr;
	int db_nowait;
	char* car_server_ip;
	char* exp_Res_code_ldap_missing;
	char* origin_host;
} VOWIFI_CONFIG;

typedef struct {
	int resultCode;
	char* userName;
	int httpStatusCode;
} VowifiLdapRestResponse;

extern DICT_OBJS dict_objs;
extern VOWIFI_CONFIG vowifiConfig;

struct sess_state {
	char* imsi;
	char* identity;

	uint8_t *rand; 
	size_t randLen;

	uint8_t *autn; 
	size_t autnLen;

	uint8_t *mac;
	size_t macLen;

	uint8_t *ck; 
	size_t ckLen;

	uint8_t *ik; 
	size_t ikLen;

	uint8_t *xres;   //MAR üzenetben jovo sip_authorization (610)
	size_t xresLen;

	///eszköz felől jövő értékek a challengben:
	uint8_t *c_res;   
	size_t c_resLen;

	uint8_t *c_checkcode;
	size_t c_checkcodeLen;

	uint8_t *c_mac;
	size_t c_macLen;

	//apn typus melyik apn fajtát szeretné igénybe venni ims vagy hos
	char* serviceSelection;
	
	unsigned char* eapPayload2; 
	size_t eapPayloadLen2;
	char* eapPayload2Hex; // Hex string representation of eapPayload2

	unsigned char* eapPayload; 
	size_t eapPayloadLen;
};

typedef struct {
    uint8_t res[32];        // AT_RES értéke (max 32 bájt)
    size_t res_len;         // AT_RES tényleges hossza bájtokban

    uint8_t checkcode[2];   // AT_CHECKCODE (2 bájt "reserved" mező)
    size_t checkcode_len;   // AT_CHECKCODE hossza (mindig 2)

    uint8_t mac[16];        // AT_MAC értéke (mindig 16 bájt)
    size_t mac_len;         // AT_MAC hossza (mindig 16)

    int found_mask;         // Bitmaszk, ami jelzi, mely attribútumokat találtuk meg
} EapAkaAttributes;

// TODO free a session lezarasakor

static inline int initState(struct sess_state *state) {
    CHECK_PARAMS(state);
    state->ck = NULL;
	state->ckLen = 0;
	state->autn = NULL;
	state->autnLen = 0;
	state->mac = NULL;
	state->macLen = 0;
	state->rand = NULL;
	state->randLen = 0;
    state->eapPayload = NULL;
	state->eapPayloadLen = 0;
    state->identity = NULL;
    state->ik = NULL;
	state->ikLen = 0;
    state->imsi = NULL;
    state->serviceSelection = NULL;
    state->xres = NULL;
    state->xresLen = 0;
    state->c_res = NULL;
    state->c_resLen = 0;
    state->c_checkcode = NULL;
    state->c_checkcodeLen = 0;
    state->c_mac = NULL;
    state->c_macLen = 0;
    state->eapPayload2 = NULL;
    state->eapPayloadLen2 = 0;
    state->eapPayload2Hex = NULL;
    return 0;
}
extern struct session_handler * vowifi_session_handler;

#endif  /*__VOWIFI_H__ */
