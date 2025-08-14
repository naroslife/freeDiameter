/*********************************************************************************************************
* VoWiFi Plugin for app_radgw - Handles EAP-AKA authentication for VoWiFi                                *
* Based on rgwx_auth but extended for VoWiFi-specific requirements                                       *
*********************************************************************************************************/

#include "rgw_common.h"
#include <pthread.h>

/* Application IDs */
#define AI_EAP			5	/* Diameter EAP application */
#define AI_3GPP_SWM		16777264	/* 3GPP SWm interface */
#define AI_3GPP_SWX		16777265	/* 3GPP SWx interface */

/* Command codes */
#define CC_DIAMETER_EAP		268	/* DER/DEA */
#define CC_MULTIMEDIA_AUTH	303	/* MAR/MAA */

/* Plugin configuration */
struct rgwp_config {
    struct {
        /* Common Diameter AVPs */
        struct dict_object * Auth_Application_Id;
        struct dict_object * Auth_Request_Type;
        struct dict_object * Session_Id;
        struct dict_object * Origin_Host;
        struct dict_object * Origin_Realm;
        struct dict_object * Destination_Realm;
        struct dict_object * Destination_Host;
        struct dict_object * User_Name;
        struct dict_object * Result_Code;
        
        /* EAP-specific AVPs */
        struct dict_object * EAP_Payload;
        struct dict_object * EAP_Key_Name;
        struct dict_object * EAP_Master_Session_Key;
        
        /* 3GPP-specific AVPs for SWx */
        struct dict_object * SIP_Auth_Data_Item;
        struct dict_object * SIP_Number_Auth_Items;
        struct dict_object * SIP_Authentication_Scheme;
        
        /* NAS AVPs */
        struct dict_object * NAS_Identifier;
        struct dict_object * NAS_IP_Address;
        struct dict_object * NAS_Port;
        struct dict_object * NAS_Port_Type;
        struct dict_object * Service_Type;
        struct dict_object * Calling_Station_Id;
        struct dict_object * Called_Station_Id;
    } dict;
    
    struct session_handler * sess_hdl;
    char * hss_realm;  /* HSS realm for SWx interface */
    char * hss_host;   /* HSS host for direct routing */
    int auth_vector_timeout; /* Timeout for auth vector cache */
};

/* Session state to track authentication progress */
struct sess_state {
    uint8_t req_auth[16];       /* RADIUS request authenticator */
    char imsi[16];              /* User IMSI */
    uint8_t auth_vectors[5][32]; /* Cached auth vectors from HSS */
    int current_vector;         /* Current vector being used */
    int eap_aka_state;          /* EAP-AKA state machine state */
    time_t created;
};

/* Initialize the plugin */
static int vowifi_conf_parse(char * conf_file, struct rgwp_config ** state)
{
    struct rgwp_config * new;
    
    TRACE_ENTRY("%p %p", conf_file, state);
    CHECK_PARAMS(state);
    
    CHECK_MALLOC(new = malloc(sizeof(struct rgwp_config)));
    memset(new, 0, sizeof(struct rgwp_config));
    
    /* Create session handler for maintaining state */
    CHECK_FCT(fd_sess_handler_create(&new->sess_hdl, (void *)free, NULL, NULL));
    
    /* Set default configuration */
    new->hss_realm = "3gppnetwork.org";
    new->hss_host = NULL; /* Will use realm-based routing */
    new->auth_vector_timeout = 3600; /* 1 hour cache */
    
    /* TODO: Parse configuration file if provided */
    if (conf_file) {
        /* Parse VoWiFi-specific configuration */
        /* Format could be: hss_realm=xxx,hss_host=yyy,cache_timeout=zzz */
    }
    
    /* Resolve dictionary objects */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Auth-Application-Id", &new->dict.Auth_Application_Id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Auth-Request-Type", &new->dict.Auth_Request_Type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Session-Id", &new->dict.Session_Id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Origin-Host", &new->dict.Origin_Host, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Origin-Realm", &new->dict.Origin_Realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Destination-Realm", &new->dict.Destination_Realm, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Destination-Host", &new->dict.Destination_Host, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "User-Name", &new->dict.User_Name, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Result-Code", &new->dict.Result_Code, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "EAP-Payload", &new->dict.EAP_Payload, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "NAS-Identifier", &new->dict.NAS_Identifier, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "NAS-IP-Address", &new->dict.NAS_IP_Address, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "NAS-Port", &new->dict.NAS_Port, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "NAS-Port-Type", &new->dict.NAS_Port_Type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Service-Type", &new->dict.Service_Type, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Calling-Station-Id", &new->dict.Calling_Station_Id, ENOENT));
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                            "Called-Station-Id", &new->dict.Called_Station_Id, ENOENT));
    
    /* Note: Some 3GPP AVPs might not exist in default dictionary */
    /* We'll handle missing ones gracefully or add them dynamically */
    
    *state = new;
    return 0;
}

/* Cleanup */
static void vowifi_conf_free(struct rgwp_config * state)
{
    TRACE_ENTRY("%p", state);
    if (!state) return;
    
    CHECK_FCT_DO(fd_sess_handler_destroy(&state->sess_hdl, NULL), );
    free(state);
}

/* Helper: Extract IMSI from User-Name or EAP-Identity */
static int extract_imsi(uint8_t *data, size_t len, char *imsi, size_t imsi_len)
{
    /* EAP-AKA identity format: "0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org" */
    /* or simple format: "<IMSI>" */
    
    if (len > 0 && data[0] == '0') {
        /* Full NAI format */
        char *at = memchr(data, '@', len);
        if (at) {
            size_t id_len = at - (char*)data - 1; /* Skip leading '0' */
            if (id_len < imsi_len) {
                memcpy(imsi, data + 1, id_len);
                imsi[id_len] = '\0';
                return 0;
            }
        }
    }
    
    /* Simple format */
    if (len < imsi_len) {
        memcpy(imsi, data, len);
        imsi[len] = '\0';
        return 0;
    }
    
    return -1;
}

/* Helper: Send MAR to HSS to get authentication vectors */
static int fetch_auth_vectors(struct rgwp_config *cs, const char *imsi, 
                              uint8_t vectors[][32], int *num_vectors)
{
    struct msg *mar = NULL, *maa = NULL;
    struct avp *avp = NULL;
    union avp_value val;
    struct dict_object *cmd_dict = NULL;
    
    TRACE_ENTRY("%p %s %p %p", cs, imsi, vectors, num_vectors);
    
    /* Create Multimedia-Auth-Request (MAR) */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, 
                            "Multimedia-Auth-Request", &cmd_dict, ENOENT));
    CHECK_FCT(fd_msg_new(cmd_dict, MSGFL_ALLOC_ETEID, &mar));
    
    /* Add Session-Id */
    {
        struct session *sess = NULL;
        os0_t sid;
        size_t sidlen;
        CHECK_FCT(fd_sess_new(&sess, fd_g_config->cnf_diamid, 
                             fd_g_config->cnf_diamid_len, (os0_t)"vowifi", 6));
        CHECK_FCT(fd_sess_getsid(sess, &sid, &sidlen));
        CHECK_FCT(fd_msg_avp_new(cs->dict.Session_Id, 0, &avp));
        val.os.data = sid;
        val.os.len = sidlen;
        CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
        CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_FIRST_CHILD, avp));
    }
    
    /* Add Auth-Application-Id (3GPP SWx) */
    CHECK_FCT(fd_msg_avp_new(cs->dict.Auth_Application_Id, 0, &avp));
    val.u32 = AI_3GPP_SWX;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
    
    /* Add User-Name (IMSI) */
    CHECK_FCT(fd_msg_avp_new(cs->dict.User_Name, 0, &avp));
    val.os.data = (uint8_t*)imsi;
    val.os.len = strlen(imsi);
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
    
    /* Add Destination-Realm (HSS realm) */
    CHECK_FCT(fd_msg_avp_new(cs->dict.Destination_Realm, 0, &avp));
    val.os.data = (uint8_t*)cs->hss_realm;
    val.os.len = strlen(cs->hss_realm);
    CHECK_FCT(fd_msg_avp_setvalue(avp, &val));
    CHECK_FCT(fd_msg_avp_add(mar, MSG_BRW_LAST_CHILD, avp));
    
    /* TODO: Add SIP-Number-Auth-Items and SIP-Auth-Data-Item */
    
    /* Send MAR and wait for MAA */
    CHECK_FCT(fd_msg_send(&mar, NULL, NULL));
    
    /* For now, return dummy vectors */
    /* In real implementation, we'd wait for MAA and extract vectors */
    *num_vectors = 1;
    memset(vectors[0], 0xAA, 32); /* Dummy vector */
    
    return 0;
}

/* Handle incoming RADIUS request and convert to Diameter */
static int vowifi_rad_req(struct rgwp_config * cs, struct radius_msg * rad_req, 
                         struct radius_msg ** rad_ans, struct msg ** diam_fw, 
                         struct rgw_client * cli)
{
    int idx;
    struct radius_attr_hdr *attr;
    uint8_t *eap_msg = NULL;
    size_t eap_len = 0;
    struct session *sess = NULL;
    struct sess_state *st = NULL;
    union avp_value value;
    struct avp *avp = NULL;
    struct msg *req = NULL;
    os0_t sid = NULL;
    size_t sidlen;
    
    TRACE_ENTRY("%p %p %p %p %p", cs, rad_req, rad_ans, diam_fw, cli);
    CHECK_PARAMS(cs && rad_req && diam_fw);
    
    /* Check if this is an Access-Request */
    if (rad_req->hdr->code != RADIUS_CODE_ACCESS_REQUEST) {
        TRACE_DEBUG(INFO, "VoWiFi plugin: Not an Access-Request, skipping");
        return 0;
    }
    
    /* Look for EAP-Message attribute */
    for (idx = 0; idx < rad_req->attr_used; idx++) {
        attr = (struct radius_attr_hdr *)(rad_req->buf + rad_req->attr_pos[idx]);
        if (attr->type == RADIUS_ATTR_EAP_MESSAGE) {
            eap_msg = (uint8_t *)(attr + 1);
            eap_len = attr->length - sizeof(*attr);
            break;
        }
    }
    
    if (!eap_msg) {
        TRACE_DEBUG(INFO, "VoWiFi plugin: No EAP-Message found, skipping");
        return 0; /* Let other plugins handle non-EAP requests */
    }
    
    TRACE_DEBUG(INFO, "VoWiFi plugin: Processing EAP message (%zu bytes)", eap_len);
    
    /* Check if we already have a Diameter message created by another plugin */
    if (*diam_fw == NULL) {
        struct dict_object *cmd_dict = NULL;
        
        /* Create new Diameter-EAP-Request (DER) */
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, 
                                "Diameter-EAP-Request", &cmd_dict, ENOENT));
        CHECK_FCT(fd_msg_new(cmd_dict, MSGFL_ALLOC_ETEID, &req));
        *diam_fw = req;
    } else {
        req = *diam_fw;
    }
    
    /* Get or create session */
    CHECK_FCT(fd_msg_sess_get(fd_g_config->cnf_dict, req, &sess, NULL));
    if (!sess) {
        CHECK_FCT(fd_sess_new(&sess, fd_g_config->cnf_diamid, 
                             fd_g_config->cnf_diamid_len, (os0_t)"vowifi", 6));
        CHECK_FCT(fd_msg_avp_new(cs->dict.Session_Id, 0, &avp));
        CHECK_FCT(fd_sess_getsid(sess, &sid, &sidlen));
        value.os.data = sid;
        value.os.len = sidlen;
        CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
        CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_FIRST_CHILD, avp));
    }
    
    /* Store session state */
    CHECK_FCT(fd_sess_state_retrieve(cs->sess_hdl, sess, &st));
    if (!st) {
        CHECK_MALLOC(st = malloc(sizeof(struct sess_state)));
        memset(st, 0, sizeof(struct sess_state));
        memcpy(st->req_auth, rad_req->hdr->authenticator, 16);
        st->created = time(NULL);
        CHECK_FCT(fd_sess_state_store(cs->sess_hdl, sess, &st));
    }
    
    /* Add Auth-Application-Id (Diameter EAP) */
    CHECK_FCT(fd_msg_avp_new(cs->dict.Auth_Application_Id, 0, &avp));
    value.u32 = AI_EAP;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
    
    /* Add EAP-Payload */
    CHECK_FCT(fd_msg_avp_new(cs->dict.EAP_Payload, 0, &avp));
    value.os.data = eap_msg;
    value.os.len = eap_len;
    CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
    
    /* Extract and add User-Name if it's an EAP-Identity */
    if (eap_len > 5 && eap_msg[0] == 0x02 && eap_msg[4] == 0x01) {
        /* EAP Response Identity */
        char imsi[16];
        if (extract_imsi(eap_msg + 5, eap_len - 5, imsi, sizeof(imsi)) == 0) {
            strcpy(st->imsi, imsi);
            CHECK_FCT(fd_msg_avp_new(cs->dict.User_Name, 0, &avp));
            value.os.data = (uint8_t*)st->imsi;
            value.os.len = strlen(st->imsi);
            CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
            CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
            
            /* Fetch auth vectors from HSS if needed */
            if (st->current_vector == 0 && st->auth_vectors[0][0] == 0) {
                int num_vectors;
                fetch_auth_vectors(cs, st->imsi, st->auth_vectors, &num_vectors);
            }
        }
    }
    
    /* Add NAS information */
    for (idx = 0; idx < rad_req->attr_used; idx++) {
        attr = (struct radius_attr_hdr *)(rad_req->buf + rad_req->attr_pos[idx]);
        
        switch (attr->type) {
        case RADIUS_ATTR_NAS_IP_ADDRESS:
            CHECK_FCT(fd_msg_avp_new(cs->dict.NAS_IP_Address, 0, &avp));
            value.os.data = (uint8_t *)(attr + 1);
            value.os.len = attr->length - sizeof(*attr);
            CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
            CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
            break;
            
        case RADIUS_ATTR_NAS_IDENTIFIER:
            CHECK_FCT(fd_msg_avp_new(cs->dict.NAS_Identifier, 0, &avp));
            value.os.data = (uint8_t *)(attr + 1);
            value.os.len = attr->length - sizeof(*attr);
            CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
            CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
            break;
            
        case RADIUS_ATTR_CALLING_STATION_ID:
            CHECK_FCT(fd_msg_avp_new(cs->dict.Calling_Station_Id, 0, &avp));
            value.os.data = (uint8_t *)(attr + 1);
            value.os.len = attr->length - sizeof(*attr);
            CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
            CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
            break;
            
        case RADIUS_ATTR_CALLED_STATION_ID:
            CHECK_FCT(fd_msg_avp_new(cs->dict.Called_Station_Id, 0, &avp));
            value.os.data = (uint8_t *)(attr + 1);
            value.os.len = attr->length - sizeof(*attr);
            CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
            CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
            break;
        }
    }
    
    /* Add Destination-Realm */
    CHECK_FCT(fd_msg_avp_new(cs->dict.Destination_Realm, 0, &avp));
    value.os.data = (uint8_t*)"epc.mnc001.mcc001.3gppnetwork.org";
    value.os.len = strlen((char*)value.os.data);
    CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
    
    /* Add Auth-Request-Type */
    CHECK_FCT(fd_msg_avp_new(cs->dict.Auth_Request_Type, 0, &avp));
    value.u32 = 3; /* AUTHORIZE_AUTHENTICATE */
    CHECK_FCT(fd_msg_avp_setvalue(avp, &value));
    CHECK_FCT(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp));
    
    TRACE_DEBUG(INFO, "VoWiFi plugin: Created DER, ready to forward");
    
    return 0; /* Continue processing */
}

/* Handle incoming Diameter answer and convert to RADIUS */
static int vowifi_diam_ans(struct rgwp_config * cs, struct msg ** diam_ans, 
                          struct radius_msg ** rad_fw, struct rgw_client * cli)
{
    struct msg_hdr *hdr = NULL;
    struct avp *avp = NULL;
    struct avp_hdr *ahdr = NULL;
    struct radius_msg *rad_ans = NULL;
    struct session *sess = NULL;
    struct sess_state *st = NULL;
    
    TRACE_ENTRY("%p %p %p %p", cs, diam_ans, rad_fw, cli);
    CHECK_PARAMS(cs && diam_ans && *diam_ans && rad_fw);
    
    /* Get message header */
    CHECK_FCT(fd_msg_hdr(*diam_ans, &hdr));
    
    /* Check if this is a Diameter-EAP-Answer */
    if ((hdr->msg_code != CC_DIAMETER_EAP) || (hdr->msg_flags & CMD_FLAG_REQUEST)) {
        TRACE_DEBUG(INFO, "VoWiFi plugin: Not a DEA, skipping");
        return 0;
    }
    
    TRACE_DEBUG(INFO, "VoWiFi plugin: Processing DEA");
    
    /* Get session and state */
    CHECK_FCT(fd_msg_sess_get(fd_g_config->cnf_dict, *diam_ans, &sess, NULL));
    if (sess) {
        CHECK_FCT(fd_sess_state_retrieve(cs->sess_hdl, sess, &st));
    }
    
    /* Create RADIUS response if not already created */
    if (*rad_fw == NULL) {
        CHECK_MALLOC(rad_ans = radius_msg_new(RADIUS_CODE_ACCESS_CHALLENGE, 0));
        *rad_fw = rad_ans;
    } else {
        rad_ans = *rad_fw;
    }
    
    /* Process DEA AVPs */
    /* Look for Result-Code */
    CHECK_FCT(fd_msg_search_avp(*diam_ans, cs->dict.Result_Code, &avp));
    if (avp) {
        CHECK_FCT(fd_msg_avp_hdr(avp, &ahdr));
        /* Check result code */
        if (ahdr->avp_value->u32 == 2001) { /* DIAMETER_SUCCESS */
            rad_ans->hdr->code = RADIUS_CODE_ACCESS_ACCEPT;
        } else if (ahdr->avp_value->u32 == 1001) { /* DIAMETER_MULTI_ROUND_AUTH */
            rad_ans->hdr->code = RADIUS_CODE_ACCESS_CHALLENGE;
        } else {
            rad_ans->hdr->code = RADIUS_CODE_ACCESS_REJECT;
        }
    }
    
    /* Look for EAP-Payload */
    CHECK_FCT(fd_msg_search_avp(*diam_ans, cs->dict.EAP_Payload, &avp));
    if (avp) {
        CHECK_FCT(fd_msg_avp_hdr(avp, &ahdr));
        /* Add EAP-Message to RADIUS */
        if (!radius_msg_add_attr(rad_ans, RADIUS_ATTR_EAP_MESSAGE, 
                                ahdr->avp_value->os.data, 
                                ahdr->avp_value->os.len)) {
            TRACE_DEBUG(INFO, "Failed to add EAP-Message");
        }
    }
    
    /* Add Message-Authenticator */
    uint8_t msg_auth[16] = {0};
    radius_msg_add_attr(rad_ans, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, msg_auth, 16);
    
    /* Copy authenticator from request if we have state */
    if (st) {
        memcpy(rad_ans->hdr->authenticator, st->req_auth, 16);
    }
    
    TRACE_DEBUG(INFO, "VoWiFi plugin: Created RADIUS response (code=%d)", 
                rad_ans->hdr->code);
    
    return 0; /* Continue processing */
}

/* Export the plugin descriptor */
struct rgw_api rgwp_descriptor = {
    .rgwp_name       = "vowifi",
    .rgwp_conf_parse = vowifi_conf_parse,
    .rgwp_conf_free  = vowifi_conf_free,
    .rgwp_rad_req    = vowifi_rad_req,
    .rgwp_diam_ans   = vowifi_diam_ans
};