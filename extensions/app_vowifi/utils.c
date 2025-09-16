#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// EAP-AKA/SIM Attribute Types (RFC 4187)
#define AT_RES          0x04
#define AT_CHECKCODE    0x0C
#define AT_MAC          0x0B

#define AT_RAND          0x03
#define AT_AUTH          0x86

// A talált attribútumok jelzésére szolgáló bitmaszkok
#define FOUND_RES       (1 << 0)
#define FOUND_CHECKCODE (1 << 1)
#define FOUND_MAC       (1 << 2)

int vowifi_substring(const char* src, int startPosition, char until, char** dest) {
    if (src == NULL || dest == NULL || startPosition < 0 || startPosition >= strlen(src)) {
        return -1;
    }

    int i = startPosition;
    int length = 0;

    while (src[i] != '\0' && src[i] != until) {
        length++;
        i++;
    }

    *dest = (char*)malloc((length + 1) * sizeof(char));
    if (*dest == NULL) {
        return -1; // Malloc hiba
    }

    strncpy(*dest, src + startPosition, length);
    (*dest)[length] = '\0';

    return 0;
}

// dest dinamikusan foglalva, src felszabaditva
int vowifi_ltrim_zeros(char* src, char** dest) {
    if (src == NULL || dest == NULL) {
        return -1; // Hibás paraméterek
    }

    size_t start = 0;

    while (src[start] == '0') {
        start++;
    }

    if (start == 0) { // nincs teendo, nincs az elejen 0 karakter
        return 0;
    }

    // Ha nem maradt karakter, akkor az üres stringet kell visszaadni
    if (src[start] == '\0') {
        *dest = (char*)malloc(1 * sizeof(char)); // Csak a null terminátor
        if (*dest == NULL) {
            return -1; // Memóriafoglalási hiba
        }
        (*dest)[0] = '\0';
        free(src);
        return 0;
    }

    size_t newLen = strlen(src) - start;

    *dest = (char*)malloc((newLen + 1) * sizeof(char));
    if (*dest == NULL) {
        return -1;
    }

    strcpy(*dest, src + start);
    free(src);

    return 0;
}

// TODO check free, minden hivasnal
int getStringFromMsg(struct msg *msg, char** strAddr, int avpCode) {
    struct avp *avp = NULL;
    struct avp_hdr *hdr = NULL;

    CHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &avp, NULL));
    while (avp) {
        CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
        if (hdr->avp_code == avpCode) { // User-Name
            char* str = (char*)malloc(hdr->avp_value->os.len + 1);
            if (str == NULL) {
                return -1;
            }
            memcpy(str, hdr->avp_value->os.data, hdr->avp_value->os.len);
            str[hdr->avp_value->os.len] = '\0';
            *strAddr = str;
            return 0;
        }
        CHECK_FCT(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL));
    }
    return -1; // User-Name AVP not found
}

int getSessionIdFromMsg(struct msg *msg, char** sessionIdAddr) {
    int res = getStringFromMsg(msg, sessionIdAddr, 263); // Session-Id
    
    /*
    struct avp *session_avp = NULL;
    struct avp_hdr *session_hdr = NULL;

    CHECK_FCT(fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &session_avp, NULL));
	while (session_avp) {
		CHECK_FCT(fd_msg_avp_hdr(session_avp, &session_hdr));
		if (session_hdr->avp_code == 263) { // Session-Id
            char* sessionId = (char*)malloc(session_hdr->avp_value->os.len + 1);
            if (sessionId == NULL) {
                return -1;
            }
            memcpy(sessionId, session_hdr->avp_value->os.data, session_hdr->avp_value->os.len);
            sessionId[session_hdr->avp_value->os.len] = '\0';
            *sessionIdAddr = sessionId;
            return 0;
		}
		CHECK_FCT(fd_msg_browse(session_avp, MSG_BRW_NEXT, &session_avp, NULL));
	}
    */
    return res;
}

int register_handler(int applicationId, int commandCode, int avpCode, int cmdCriteria,
                     int (*cb)( struct msg **, struct avp *, struct session *, void *, enum disp_action *), 
                    struct disp_hdl ** handle, int auth, int acct) {
    struct disp_when when;
    struct dict_object *cmd;
	struct dict_object *app;

    when.app = NULL;
    when.command = NULL;
    when.avp = NULL;
    when.value = NULL;

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
		                          APPLICATION_BY_ID, &applicationId, 
		                          &app, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, 
		                          CMD_BY_CODE_R, &commandCode, 
		                          &cmd, ENOENT));                              
    when.app = app;
    when.command = cmd; 
    
    if (avpCode != 0) {
        struct dict_object *avp;
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, 
                                  AVP_BY_CODE, &avpCode, 
                                  &avp, ENOENT));
        when.avp = avp;
    }

    CHECK_FCT(fd_disp_register(cb, DISP_HOW_CC, &when, NULL, handle));
    CHECK_FCT(fd_disp_app_support ( app, NULL, auth, acct ) );                                
    return 0;                                
}

int createMessageBase(int applicationId, int commandCode, struct msg ** msg) {
    struct msg *newMsg = NULL;
    struct dict_object *cmd = NULL;
    struct dict_object *app = NULL;
    struct msg_hdr *hdr;
    //struct dict_cmd_data cmd_data;

    //cmd_data.cmd_code = commandCode;
    //cmd_data.cmd_flag_val = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;
    //cmd_data.cmd_flag_mask = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
                           APPLICATION_BY_ID, &applicationId, 
                           &app, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, 
                           CMD_BY_CODE_R, &commandCode, 
                           &cmd, ENOENT));

    // Create message
	if (cmd) {
		CHECK_FCT(fd_msg_new(cmd, MSGFL_ALLOC_ETEID, &newMsg));
        CHECK_FCT(fd_msg_hdr(newMsg, &hdr));
        hdr->msg_appl = applicationId;
	} else {
		// Create message manually if dictionary doesn't have MAR
		CHECK_FCT(fd_msg_new(NULL, MSGFL_ALLOC_ETEID, &newMsg));
		// Set command code manually
		CHECK_FCT(fd_msg_hdr(newMsg, &hdr));
		hdr->msg_code = commandCode;
		hdr->msg_flags = CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE;
		hdr->msg_appl = applicationId;
	}
    *msg = newMsg;

    return 0;
}

// TODO rekurzio
int addAvpFromMessage(struct msg * srcMsg, struct msg * destMsg, struct dict_object * avp, int avpCode) {
    struct avp *srcAvp = NULL;
    struct avp *newAvp = NULL;
    struct avp_hdr *hdr;
    union avp_value val;

    CHECK_FCT(fd_msg_browse(srcMsg, MSG_BRW_FIRST_CHILD, &srcAvp, NULL));
    while (srcAvp) {
        CHECK_FCT(fd_msg_avp_hdr(srcAvp, &hdr));
        if (hdr->avp_code == avpCode) {
            CHECK_FCT(fd_msg_avp_new(avp, 0, &newAvp));
            if (hdr->avp_value != NULL) {
                val = *(hdr->avp_value);
                CHECK_FCT(fd_msg_avp_setvalue(newAvp, &val));
                CHECK_FCT(fd_msg_avp_add(destMsg, MSG_BRW_LAST_CHILD, newAvp));
            }
            return 0; // Successfully added
        }
        CHECK_FCT(fd_msg_browse(srcAvp, MSG_BRW_NEXT, &srcAvp, NULL));
    }
    return -1; // AVP not found in source message
}

// TODO rekurzio
int addAvpFromMessageByAvpCode(struct msg * srcMsg, struct msg * destMsg, int avpCode) {
    struct dict_object * avp = NULL;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE, &avpCode, &avp, ENOENT));
    CHECK_FCT(addAvpFromMessage(srcMsg, destMsg, avp, avpCode));
    return 0;
}

int addAvpFromMessageByAvpCodeArray(struct msg * srcMsg, struct msg * destMsg, int avpCodes[], int count) {
    for (size_t i = 0; i < count; i++) {
        //CHECK_FCT(addAvpFromMessageByAvpCode(srcMsg, destMsg, avpCodes[i]));
        addAvpFromMessageByAvpCode(srcMsg, destMsg, avpCodes[i]);
    }
    return 0;
}

int addAvp(struct msg * msg, struct dict_object * avp, union avp_value * val) {
    struct avp * newAvp = NULL;
    CHECK_FCT(fd_msg_avp_new(avp, 0, &newAvp));
    CHECK_FCT(fd_msg_avp_setvalue(newAvp, val));
    CHECK_FCT(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, newAvp));
    return 0;
}

int addAvpByAvpCode(struct msg * msg, int avpCode, union avp_value * val) {
    struct dict_object * avp = NULL;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE, &avpCode, &avp, ENOENT));
    CHECK_FCT(addAvp(msg, avp, val));
    return 0;
}

int addAvpInt32(struct msg * msg, struct dict_object * avp, int32_t val) {
    union avp_value v;
    v.i32 = val;
    CHECK_FCT(addAvp(msg, avp, &v));
    return 0;
}

int addAvpInt32ByAvpCode(struct msg * msg, int avpCode, int32_t val) {
    struct dict_object * avp = NULL;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE, &avpCode, &avp, ENOENT));
    CHECK_FCT(addAvpInt32(msg, avp, val));
    return 0;
}

int addAvpStr(struct msg * msg, struct dict_object * avp, uint8_t* val) {
    union avp_value v;
    v.os.data = val;
    v.os.len = strlen((const char*)val);
    CHECK_FCT(addAvp(msg, avp, &v));
    return 0;
}

int addAvpStrByAvpCode(struct msg * msg, int avpCode, uint8_t* val) {
    union avp_value v;
    v.os.data = val;
    v.os.len = strlen((const char*)val);
    CHECK_FCT(addAvpByAvpCode(msg, avpCode, &v));
    return 0;
}

int addAvpBytes(struct msg * msg, struct dict_object * avp, uint8_t* val, size_t len) {
    union avp_value v;
    v.os.data = val;
    v.os.len = len;
    CHECK_FCT(addAvp(msg, avp, &v));
    return 0;
}
int addAvpBytesByAvpCode(struct msg * msg, int avpCode, uint8_t* val, size_t len) {
    union avp_value v;
    v.os.data = val;
    v.os.len = len;
    CHECK_FCT(addAvpByAvpCode(msg, avpCode, &v));
    return 0;
}

int addVendorSpecificApplicationId(struct msg * msg, uint32_t vendor_id, uint32_t app_id) {
    struct avp *avp;

	struct dict_avp_request req;
	memset(&req, 0, sizeof(struct dict_avp_request));
	req.avp_vendor = vendor_id; // 3GPP
	req.avp_code = 260;

    struct dict_object *expResult = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                   "Vendor-Specific-Application-Id", &expResult, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(expResult, 0, &avp));

		struct dict_object *vendorId = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                  	"Vendor-Id", &vendorId, ENOENT) == 0) {					
			struct avp *vendorIdAvp;
			fd_msg_avp_new(vendorId, 0, &vendorIdAvp);
			fd_msg_avp_setvalue(vendorIdAvp, &(union avp_value){ .u32 = vendor_id });
			fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, vendorIdAvp);
		}
		fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp);

		struct dict_object *expResultCode = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                  	"Auth-Application-Id", &expResultCode, ENOENT) == 0) {					
			struct avp *expResultCodeAvp;
			fd_msg_avp_new(expResultCode, 0, &expResultCodeAvp);
			fd_msg_avp_setvalue(expResultCodeAvp, &(union avp_value){ .u32 = app_id });
			fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, expResultCodeAvp);
		}
		fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp);

	}
    return 0;
}

int addExperimentalResultCode(struct msg * msg, uint32_t vendor_id, uint32_t avpCode, uint32_t resultCode) {
    struct avp *avp;

	struct dict_avp_request req;
	memset(&req, 0, sizeof(struct dict_avp_request));
	req.avp_vendor = vendor_id; // 3GPP
	req.avp_code = avpCode; // Experimental-Result

    struct dict_object *expResult = NULL;
	if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE_AND_VENDOR, 
	                   &req, &expResult, ENOENT) == 0) {
		CHECK_FCT(fd_msg_avp_new(expResult, 0, &avp));

		struct dict_object *vendorId = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                  	"Vendor-Id", &vendorId, ENOENT) == 0) {					
			struct avp *vendorIdAvp;
			fd_msg_avp_new(vendorId, 0, &vendorIdAvp);
			fd_msg_avp_setvalue(vendorIdAvp, &(union avp_value){ .u32 = vendor_id });
			fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, vendorIdAvp);
		}
		fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp);

		struct dict_object *expResultCode = NULL;
		if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
		                  	"Experimental-Result-Code", &expResultCode, ENOENT) == 0) {					
			struct avp *expResultCodeAvp;
			fd_msg_avp_new(expResultCode, 0, &expResultCodeAvp);
			fd_msg_avp_setvalue(expResultCodeAvp, &(union avp_value){ .u32 = resultCode });
			fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, expResultCodeAvp);
		}
		fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp);

	}
    return 0;
}

int getDictObjectByName(const char* name, enum dict_object_type type, struct dict_object ** obj) {
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, type, 
                           (type == DICT_AVP) ? AVP_BY_NAME :
                           (type == DICT_COMMAND) ? CMD_BY_NAME :
                           (type == DICT_APPLICATION) ? APPLICATION_BY_NAME :
                           (type == DICT_VENDOR) ? VENDOR_BY_NAME :
                           ENOENT, 
                           name, 
                           obj, ENOENT));
    return 0;
}

int getAvpFromMessage(struct msg * srcMsg, int avpCode, struct avp ** destAvp) {
    struct avp *srcAvp = NULL;

    CHECK_FCT(fd_msg_browse(srcMsg, MSG_BRW_FIRST_CHILD, &srcAvp, NULL));
    while (srcAvp) {
        struct avp_hdr *hdr;
        CHECK_FCT(fd_msg_avp_hdr(srcAvp, &hdr));
        if (hdr->avp_code == avpCode) {
            *destAvp = srcAvp;
            return 0; // Successfully found
        }
        CHECK_FCT(fd_msg_browse(srcAvp, MSG_BRW_NEXT, &srcAvp, NULL));
    }
    return -1; // AVP not found in source message
}

int getAvpChildFromMessage(struct msg * srcMsg, int parentAvpCode, int avpCode, struct avp ** destAvp) {
    struct avp *parentAvp = NULL;
    if (getAvpFromMessage(srcMsg, parentAvpCode, &parentAvp) != 0) {
        return -1; // Parent AVP not found
    }

    struct avp *childAvp = NULL;
    CHECK_FCT(fd_msg_browse(parentAvp, MSG_BRW_FIRST_CHILD, &childAvp, NULL));
    while (childAvp) {
        struct avp_hdr *hdr;
        CHECK_FCT(fd_msg_avp_hdr(childAvp, &hdr));
        if (hdr->avp_code == avpCode) {
            *destAvp = childAvp;
            return 0; // Successfully found
        }
        CHECK_FCT(fd_msg_browse(childAvp, MSG_BRW_NEXT, &childAvp, NULL));
    }
    return -1; // Child AVP not found
}

int getResultCodeFromMessage(struct msg * msg, uint32_t * resultCode) {
    struct avp *resultCodeAvp = NULL;
    if (getAvpFromMessage(msg, 268, &resultCodeAvp) == 0) { // Result-Code
        struct avp_hdr *hdr;
        CHECK_FCT(fd_msg_avp_hdr(resultCodeAvp, &hdr));
        *resultCode = hdr->avp_value->u32;
        return 0;
    }
    return -1; // Result-Code AVP not found
}

int getIntValueFromMessage(struct msg * msg, int avpCode, uint32_t * intValue) {
    struct avp *avp = NULL;
    if (getAvpFromMessage(msg, avpCode, &avp) == 0) {
        struct avp_hdr *hdr;
        CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
        if (hdr->avp_value != NULL) {
            *intValue = hdr->avp_value->u32;
            return 0;
        }
    }
    return -1; // AVP not found
}

int getChildIntValueFromMessage(struct msg * msg, int parentAvpCode, int avpCode, uint32_t * intValue) {
    struct avp *avp = NULL;
    if (getAvpChildFromMessage(msg, parentAvpCode, avpCode, &avp) == 0) {
        struct avp_hdr *hdr;
        CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
        if (hdr->avp_value != NULL) {
            *intValue = hdr->avp_value->u32;
            return 0;
        }
    }
    return -1; // AVP not found
}

int getBytesFromAvp(struct avp * avp, uint8_t** val) {
    struct avp_hdr *hdr;
    CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
    if (hdr->avp_value != NULL && hdr->avp_value->os.data != NULL && hdr->avp_value->os.len > 0) {
        size_t len = hdr->avp_value->os.len + 1;
        *val = (uint8_t*)malloc(len);
        if (*val == NULL) {
            return -1; // Memory allocation error
        }
        memcpy(*val, hdr->avp_value->os.data, len);
        val[len - 1] = '\0'; // Null-terminate the string
        return 0;
    }
    return -1; // AVP has no value
}

int getBytesFromAvpWithLength(struct avp * avp, uint8_t **val, size_t *length) {
    struct avp_hdr *hdr;
    CHECK_FCT(fd_msg_avp_hdr(avp, &hdr));
    if (hdr->avp_value != NULL && hdr->avp_value->os.data != NULL && hdr->avp_value->os.len > 0) {
        size_t len = hdr->avp_value->os.len;
        *val = (uint8_t*)malloc(len);
        if (*val == NULL) {
            return -1; // Memory allocation error
        }
        memcpy(*val, hdr->avp_value->os.data, len);
        *length = len;
        return 0;
    }
    return -1; // AVP has no value
}

int getBytesFromMessageWithLengthByAvpCode(struct msg * msg, int avpCode, uint8_t **val, size_t *length) {
    struct avp *avp = NULL;
    if (getAvpFromMessage(msg, avpCode, &avp) == 0) {
        return getBytesFromAvpWithLength(avp, val, length);
    }
    return -1; // AVP not found
}

int getBytesFromMessageByAvpCode(struct msg * msg, int avpCode, uint8_t** val) {
    struct avp *avp = NULL;
    if (getAvpFromMessage(msg, avpCode, &avp) == 0) {
        return getBytesFromAvp(avp, val);
    }
    return -1; // AVP not found
}

extern struct session_handler * vowifi_session_handler;

int createNewSession(struct msg * msg, struct session ** sess) {
    if (vowifi_session_handler == NULL) {
        return -1; // Session handler not initialized
    }

    struct session * newSession = NULL;


    os0_t sid = vowifiConfig.sessionIdSuffix;
    CHECK_FCT(fd_msg_new_session(msg, vowifiConfig.sessionIdSuffix, vowifiConfig.sessionIdSuffixLen));
    CHECK_FCT(fd_msg_sess_get(fd_g_config->cnf_dict, msg, &newSession, NULL));

	size_t sidlen;
    fd_sess_getsid( newSession, &sid, &sidlen);
    printf("Created new session with Session-Id: %.*s\n", (int)sidlen, sid);
    if (newSession == NULL) {
        return -1; // Failed to create session
    }

    *sess = newSession;
    return 0;
}

int storeState(struct session * sess, struct sess_state * state) {
    CHECK_FCT(fd_sess_state_store (vowifi_session_handler, sess, &state));
    return 0;
}

/*
int initState(struct sess_state *state) {
    CHECK_PARAMS(state);
    state->ckHex = NULL;
    state->eapPayload = NULL;
    state->identity = NULL;
    state->ikHex = NULL;
    state->imsi = NULL;
    return 0;
}
    */

int allocAndInitState(struct sess_state **state) {
    CHECK_PARAMS(state);
    if (*state == NULL) {
        CHECK_MALLOC(*state = malloc(sizeof(struct sess_state)));
        CHECK_FCT(initState(*state));
    }
    return 0;
}

int getOrCreateSessionState(struct msg *msg, struct session ** session, struct sess_state **state) {
    int isNew;
    CHECK_FCT(fd_msg_sess_get(fd_g_config->cnf_dict, msg, session, &isNew));
    fd_sess_state_retrieve(vowifi_session_handler, *session, state);
    
    //if (*state == NULL) { Nem itt kell feltolteni, hanem ahol hasznaljuk
    //    allocAndInitState(state);
    //    fd_sess_state_store(vowifi_session_handler, *session, state);
    //}
    return 0;
}

int retrieveState(struct session * sess, struct sess_state** state) {
    CHECK_FCT(fd_sess_state_retrieve(vowifi_session_handler, sess, state));
    return 0;
}

int debugPrintMsg(struct msg * msg) {
    char* buffer = NULL;
    size_t buffer_size = 0;
    fd_msg_dump_treeview(&buffer, &buffer_size, NULL, msg, fd_g_config->cnf_dict, 1, 1);
    if (buffer) {
        printf("Message dump:\n%s\n", buffer);
        free(buffer);
    } else {
        printf("Failed to dump message\n");
    }
    return 0;
}


int parse_eap_payload(const uint8_t* payload, size_t payload_len, EapAkaAttributes* attrs) {
    if (payload == NULL || attrs == NULL) {
        return -1; // Invalid arguments
    }
    // Struktúra inicializálása
    memset(attrs, 0, sizeof(EapAkaAttributes));

    // Az EAP üzenet hossza a 3. és 4. bájtban van.
    // Ellenőrizzük, hogy a kapott hossz egyezik-e ezzel.
    if (payload_len < 4) {
        fprintf(stderr, "Error: Payload is too short for an EAP header.\n");
        return -2;
    }
    size_t eap_len = (payload[2] << 8) | payload[3];
    if (eap_len != payload_len) {
        fprintf(stderr, "Warning: Actual payload length (%zu) differs from EAP header length (%zu).\n", payload_len, eap_len);
    }

    // Az EAP-AKA/SIM attribútumok az EAP-AKA header (Type, Subtype, Reserved) után kezdődnek.
    // EAP Header (4 bytes) + AKA Type (1 byte) + AKA Subtype (1 byte) + Reserved (2 bytes) = 8 bytes
    size_t offset = 8;

    while (offset < payload_len) {
        // Ellenőrizzük, van-e elég hely a Type és Length mezőknek
        if (offset + 2 > payload_len) {
            fprintf(stderr, "Error: Malformed attribute header at offset %zu.\n", offset);
            break;
        }

        uint8_t type = payload[offset];
        uint8_t len_words = payload[offset + 1]; // Length in 32-bit words
        size_t attr_len_bytes = (size_t)len_words * 4;

        // Hibás hossz, ami végtelen ciklust okozhatna
        if (attr_len_bytes == 0) {
             fprintf(stderr, "Error: Attribute with zero length found at offset %zu.\n", offset);
             break;
        }

        // Ellenőrizzük, hogy az attribútum belefér-e a payloadba
        if (offset + attr_len_bytes > payload_len) {
            fprintf(stderr, "Error: Attribute length exceeds payload boundary at offset %zu.\n", offset);
            break;
        }

        // A releváns attribútumok feldolgozása
        switch (type) {
            case AT_MAC:
                // Az AT_MAC teljes hossza 5*4=20 bájt (Type, Length, Reserved(2), MAC(16))
                if (attr_len_bytes == 20) {
                    memcpy(attrs->mac, payload + offset + 4, 16);
                    attrs->mac_len = 16;
                    attrs->found_mask |= FOUND_MAC;
                }
                break;

            case AT_RES:
            case AT_RAND:
                // A tényleges RES hossza a Value mező első 2 bájtjában van (bitekben)
                if (attr_len_bytes >= 4) {
                    uint16_t res_len_bits = (payload[offset + 2] << 8) | payload[offset + 3];
                    size_t res_len_bytes = (res_len_bits + 7) / 8; // Kerekítés fel bájtokra

                    if (res_len_bytes <= sizeof(attrs->res) && (4 + res_len_bytes) <= attr_len_bytes) {
                        memcpy(attrs->res, payload + offset + 4, res_len_bytes);
                        attrs->res_len = res_len_bytes;
                        attrs->found_mask |= FOUND_RES;
                    }
                }
                break;

            case AT_CHECKCODE:
            case AT_AUTH:
                // Az AT_CHECKCODE teljes hossza 1*4=4 bájt (Type, Length, Reserved(2))
                if (attr_len_bytes == 4) {
                    memcpy(attrs->checkcode, payload + offset + 2, 2);
                    attrs->checkcode_len = 2;
                    attrs->found_mask |= FOUND_CHECKCODE;
                }
                break;
        }

        // Ugrás a következő attribútumra
        offset += attr_len_bytes;
    }

    return attrs->found_mask;
}

/**
 * @brief Egy hexadecimális karaktert konvertál integer értékké.
 * @param c A hexadecimális karakter.
 * @return Az integer érték, vagy -1 hiba esetén.
 */
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Egy hexadecimális stringet konvertál bájt tömbbé.
 * @param hex A bemeneti hex string.
 * @param bytes A kimeneti bájt tömb.
 * @param max_len A kimeneti tömb maximális mérete.
 * @return A konvertált bájtok száma.
 */
size_t hex_string_to_bytes(const char* hex, uint8_t* bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return 0; // Hibás hossz
    }
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) {
        byte_len = max_len;
    }
    for (size_t i = 0; i < byte_len; ++i) {
        int high = hex_char_to_int(hex[i * 2]);
        int low = hex_char_to_int(hex[i * 2 + 1]);
        if (high == -1 || low == -1) {
            return 0; // Hibás karakter
        }
        bytes[i] = (high << 4) | low;
    }
    return byte_len;
}