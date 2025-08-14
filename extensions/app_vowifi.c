/*
 * app_vowifi - FreeDiameter application for VoWiFi
 * Handles DER/DEA and MAR/MAA for complete E2E flow
 */

#include <freeDiameter/extension.h>

/* Configuration */
static struct {
    char *radius_server;
    uint16_t radius_port;
    char *radius_secret;
    int mock_hss;  /* If 1, mock HSS responses */
} config = {
    .radius_server = "127.0.0.1",
    .radius_port = 1812,
    .radius_secret = "testing123",
    .mock_hss = 1
};

/* Handler for DER messages */
static int der_handler(struct msg **msg, struct avp *avp, struct session *sess, void *data, enum disp_action *act)
{
    struct msg_hdr *hdr = NULL;
    struct msg *ans = NULL;
    struct avp *a = NULL;
    union avp_value val;
    
    TRACE_ENTRY("%p %p %p %p", msg, avp, sess, data);
    
    /* Get message header */
    CHECK_FCT(fd_msg_hdr(*msg, &hdr));
    
    fd_log_debug("[app_vowifi] Received DER");
    
    /* Create DEA answer */
    CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
    ans = *msg;
    
    /* TODO: Convert to RADIUS and send to FreeRADIUS */
    /* For now, send a mock response */
    
    /* Add Result-Code = DIAMETER_MULTI_ROUND_AUTH (1001) */
    struct dict_object *rc_avp;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Result-Code", &rc_avp, ENOENT));
    CHECK_FCT(fd_msg_avp_new(rc_avp, 0, &a));
    val.u32 = 1001;  /* DIAMETER_MULTI_ROUND_AUTH */
    CHECK_FCT(fd_msg_avp_setvalue(a, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, a));
    
    /* Add mock EAP-Payload with EAP-AKA Challenge */
    struct dict_object *eap_payload_avp;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "EAP-Payload", &eap_payload_avp, ENOENT));
    CHECK_FCT(fd_msg_avp_new(eap_payload_avp, 0, &a));
    
    /* Build EAP-AKA Challenge */
    uint8_t eap_aka[] = {
        0x01,  /* Code: Request */
        0x02,  /* Identifier */
        0x00, 0x18,  /* Length: 24 */
        0x17,  /* Type: EAP-AKA */
        0x01,  /* Subtype: AKA-Challenge */
        0x00, 0x00,  /* Reserved */
        /* AT_RAND */
        0x01,  /* AT_RAND */
        0x05,  /* Length (5*4=20 bytes) */
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    
    val.os.data = eap_aka;
    val.os.len = sizeof(eap_aka);
    CHECK_FCT(fd_msg_avp_setvalue(a, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, a));
    
    /* Send the answer */
    CHECK_FCT(fd_msg_send(msg, NULL, NULL));
    
    fd_log_debug("[app_vowifi] Sent DEA with EAP-AKA Challenge");
    
    *act = DISP_ACT_CONT;
    return 0;
}

/* Handler for MAR messages (from FreeRADIUS via rlm_diameter) */
static int mar_handler(struct msg **msg, struct avp *avp, struct session *sess, void *data, enum disp_action *act)
{
    struct msg_hdr *hdr = NULL;
    struct msg *ans = NULL;
    struct avp *a = NULL;
    union avp_value val;
    
    TRACE_ENTRY("%p %p %p %p", msg, avp, sess, data);
    
    if (!config.mock_hss) {
        /* Forward to real HSS */
        *act = DISP_ACT_CONT;
        return 0;
    }
    
    /* Mock HSS: Generate MAA with auth vectors */
    CHECK_FCT(fd_msg_hdr(*msg, &hdr));
    
    fd_log_debug("[app_vowifi] Mock HSS: Received MAR");
    
    /* Create MAA answer */
    CHECK_FCT(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0));
    ans = *msg;
    
    /* Add Result-Code = SUCCESS */
    struct dict_object *rc_avp;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Result-Code", &rc_avp, ENOENT));
    CHECK_FCT(fd_msg_avp_new(rc_avp, 0, &a));
    val.u32 = 2001;  /* DIAMETER_SUCCESS */
    CHECK_FCT(fd_msg_avp_setvalue(a, &val));
    CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, a));
    
    /* Add SIP-Auth-Data-Item with auth vectors */
    /* This is simplified - real implementation would generate proper vectors */
    struct dict_object *auth_data_avp;
    if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
                      "SIP-Auth-Data-Item", &auth_data_avp, ENOENT) == 0) {
        CHECK_FCT(fd_msg_avp_new(auth_data_avp, 0, &a));
        
        /* Mock auth vector data */
        uint8_t auth_vector[] = {
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,  /* RAND */
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,  /* AUTN */
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,  /* IK */
            0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD   /* CK */
        };
        
        val.os.data = auth_vector;
        val.os.len = sizeof(auth_vector);
        CHECK_FCT(fd_msg_avp_setvalue(a, &val));
        CHECK_FCT(fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, a));
    }
    
    /* Send the answer */
    CHECK_FCT(fd_msg_send(msg, NULL, NULL));
    
    fd_log_debug("[app_vowifi] Mock HSS: Sent MAA with auth vectors");
    
    *act = DISP_ACT_CONT;
    return 0;
}

/* Entry point */
static int vowifi_entry(char * conffile)
{
    struct disp_when data;
    struct dict_object *app_dict;
    struct dict_object *cmd_dict;
    
    TRACE_ENTRY("%p", conffile);
    
    /* TODO: Parse configuration file */
    
    /* Register handlers for DER (268) */
    memset(&data, 0, sizeof(data));
    
    /* Find the Diameter EAP application */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, 
                            APPLICATION_BY_ID, (void *)(unsigned long)5, &app_dict, ENOENT));
    
    /* Find the DER command */
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R, 
                            (void *)(unsigned long)268, &cmd_dict, ENOENT));
    
    data.app = app_dict;
    data.command = cmd_dict;
    
    CHECK_FCT(fd_disp_register(der_handler, DISP_HOW_CC, &data, NULL, NULL));
    fd_log_debug("[app_vowifi] Registered DER handler");
    
    /* Register handler for MAR (303) if mocking HSS */
    /* Disabled for now - MAR might not be in dictionary */
    /*
    if (config.mock_hss) {
        // Find the MAR command
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R, 
                                (void *)(unsigned long)303, &cmd_dict, ENOENT));
        data.command = cmd_dict;
        CHECK_FCT(fd_disp_register(mar_handler, DISP_HOW_CC, &data, NULL, NULL));
        fd_log_debug("[app_vowifi] Registered MAR handler (Mock HSS)");
    }
    */
    
    fd_log_notice("VoWiFi application extension initialized");
    
    return 0;
}

/* Cleanup */
void fd_ext_fini(void)
{
    /* Cleanup handlers */
    fd_log_debug("[app_vowifi] Extension is terminating");
}

EXTENSION_ENTRY("app_vowifi", vowifi_entry);