#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "utils.h"
#include "der_handler.h"
#include "mar_handler.h"
#include "sar_handler.h"
#include "maa_handler.h"
#include "vowifi_hook.h"
#include "test_pool.h"
#include "config_loader.h"

static int vowifi_main(char * conffile);
static int oracle_initialized = 0;

EXTENSION_ENTRY("vowifi", vowifi_main);

DICT_OBJS dict_objs;
extern VOWIFI_CONFIG vowifiConfig;

// TODO akar az osszes, az extensionben hasznalt dict_object-et cache-elhetjuk.
static int dict_init(void) {
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Session-Id", &dict_objs.Session_Id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "User-Name", &dict_objs.User_Name, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Result-Code", &dict_objs.Result_Code, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "EAP-Payload", &dict_objs.EAP_Payload, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Origin-Host", &dict_objs.Origin_Host, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Origin-Realm", &dict_objs.Origin_Realm, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Application-Id", &dict_objs.Auth_Application_Id, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Request-Type", &dict_objs.Auth_Request_Type, ENOENT));
	CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	                          "Auth-Session-State", &dict_objs.Auth_Session_State, ENOENT));
	
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "Destination-Realm", &dict_objs.Destination_Realm, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "Destination-Host", &dict_objs.Destination_Host, ENOENT);					   
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Auth-Data-Item", &dict_objs.SIP_Auth_Data_Item, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Authentication-Scheme", &dict_objs.SIP_Authentication_Scheme, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "SIP-Number-Auth-Items", &dict_objs.SIP_Number_Auth_Items, ENOENT);
	fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, 
	               "Server-Name", &dict_objs.Server_Name, ENOENT);
	
	return 0;
}

static struct disp_hdl *der3gppWsx_handler_hdl = NULL;
static struct disp_hdl *mar_handler_hdl = NULL;
//static struct disp_hdl *maa_handler_dll = NULL;
static struct disp_hdl *sar_handler_hdl = NULL;

static int initMessageHandlers() {
	register_handler(16777264, 268, 0, CMD_BY_CODE_R, vowifi_handle_der, &der3gppWsx_handler_hdl, 1, 0);  	// 3GPP-WsX application (16777264), DER command (268)
	register_handler(16777265, 303, 0, CMD_BY_CODE_R, vowifi_handle_mar, &mar_handler_hdl, 1, 0); // SWx application (16777265), MAR command (303)
	register_handler(16777265, 301, 0, CMD_BY_CODE_R, vowifi_handle_sar, &sar_handler_hdl, 1, 0); // SWx application (16777265), SAR command (301)
	//register_handler(16777265, 303, 0, CMD_BY_CODE_A, vowifi_handle_maa, &maa_handler_hdl, 1, 0); // SWx application (16777265), MAA command (303)
	return 0;
}

struct session_handler * vowifi_session_handler = NULL; 

static int initSessionHandlers() {
	CHECK_FCT(fd_sess_handler_create(&vowifi_session_handler, vowifi_hook_clear_session, NULL, NULL)); 
	return 0;
}

static int init_handlers(void) {
	initMessageHandlers();
	initSessionHandlers();
	return 0;
}

static int loadConfig(char* conffile) {
	/*
	//ezeket az értékeket konfig fájlból kellene beolvasni// Set default values first
    vowifiConfig.hssHost = (uint8_t*)strdup("gateway2.vowifi.local");
    vowifiConfig.hssRealm = (uint8_t*)strdup("vowifi.local");
    vowifiConfig.ldapRestUrl = (uint8_t*)strdup("http://cparuser:cparpass@localhost:8080/isvowifiaccess?imsi=%s");
    vowifiConfig.sessionIdSuffix = (os0_t)strdup("fd");
    vowifiConfig.sessionIdSuffixLen = strlen("fd");
    
    // Oracle default values
    vowifiConfig.db_user = getenv("ORACLE_USER") ? strdup(getenv("ORACLE_USER")) : strdup("webshop_user");
    vowifiConfig.db_pass = getenv("ORACLE_PASS") ? strdup(getenv("ORACLE_PASS")) : strdup("StrongPassword123");
    vowifiConfig.db_conn = getenv("ORACLE_CONNECT") ? strdup(getenv("ORACLE_CONNECT")) : strdup("//172.27.96.1:1521/xepdb1");
    vowifiConfig.db_minSessions = strdup("2");
    vowifiConfig.db_maxSessions = strdup("20");
    vowifiConfig.db_sessionIncr = 2;
    vowifiConfig.db_nowait = 1;
    
    // If config file is provided, override defaults
    if (conffile && strlen(conffile) > 0) {
        if (parse_config_file(conffile) != 0) {
            fd_log_error("Failed to parse config file: %s, using defaults", conffile);
        } else {
            fd_log_notice("Configuration loaded from: %s", conffile);
        }
    } else {
        fd_log_notice("No config file specified, using defaults and environment variables");
    }
		*/
	CHECK_FCT(loadConfigFromFile(conffile));
	return 0;
}

static struct fd_hook_hdl * hookhdl[2] = { NULL, NULL }; 
static int init_hooks() {
	CHECK_FCT(fd_hook_register(HOOK_MESSAGE_RECEIVED, vowifi_hook_message_received, NULL, NULL, &hookhdl[0]));
	CHECK_FCT(fd_hook_register(HOOK_MESSAGE_SENT, vowifi_hook_message_sent, NULL, NULL, &hookhdl[1]));
	return 0;
}

static int init_dbpool(void) {
	// Oracle konfiguráció environment változókból vagy config-ból
    const char *db_user = getenv("ORACLE_USER");
    if (!db_user) db_user = vowifiConfig.db_user;
    
    const char *db_pass = getenv("ORACLE_PASS");
    if (!db_pass) db_pass = vowifiConfig.db_pass;
    
    const char *db_conn = getenv("ORACLE_CONNECT");
    if (!db_conn) db_conn = vowifiConfig.db_conn;//"//192.168.100.35:1521/xepdb1";
    
    oracle_pool_cfg_t cfg = {
        .user = db_user,
        .password = db_pass,
        .connect = db_conn,
        .minSessions = vowifiConfig.db_minSessions,
        .maxSessions = vowifiConfig.db_maxSessions,
        .sessionIncr = vowifiConfig.db_sessionIncr,
        .nowait = vowifiConfig.db_nowait  // Non-blocking for production
    };
    
    if (!oracle_pool_init_singleton(&cfg)) {
        fd_log_error("[RadGW] Failed to initialize Oracle pool - using test/mock mode");
        fd_log_error("[RadGW] Oracle config: user=%s, connect=%s", db_user, db_conn);
        oracle_initialized = 0;  // Continue without Oracle
        fd_log_notice("[RadGW] Continuing without Oracle database connection");
    } else {
        oracle_initialized = 1;
        fd_log_notice("[RadGW] Oracle pool initialized successfully");
    }
	return 0;
}

static int vowifi_main(char * conffile)
{
	TRACE_ENTRY("%p", conffile);
	fprintf(stdout, __FILE__ " running on host %s.\n", fd_g_config->cnf_diamid);
	if (conffile) {
		fprintf(stdout, "Configuration file: %s\n", conffile);
	}
	CHECK_FCT(loadConfig(conffile));
	CHECK_FCT(init_hooks());
	CHECK_FCT(dict_init());
	CHECK_FCT(init_dbpool());
	CHECK_FCT(init_handlers());
	
	return 0;
}

int vowifi_main_fini() {
	if (der3gppWsx_handler_hdl) {
		fd_disp_unregister(&der3gppWsx_handler_hdl, NULL);
		der3gppWsx_handler_hdl = NULL;
	}
	if (mar_handler_hdl) {
		fd_disp_unregister(&mar_handler_hdl, NULL);
		mar_handler_hdl = NULL;
	}
	if (sar_handler_hdl) {
		fd_disp_unregister(&sar_handler_hdl, NULL);
		sar_handler_hdl = NULL;
	}
	
	if (vowifi_session_handler) {
		fd_sess_handler_destroy(&vowifi_session_handler, NULL);
		vowifi_session_handler = NULL;
	}
	
	return 0;
}
