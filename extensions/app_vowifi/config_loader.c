#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "config_loader.h"

VOWIFI_CONFIG vowifiConfig;

// Helper function to trim whitespace
static char* trim_whitespace(char* str) {
    char* end;
    
    // Trim leading space
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0)  // All spaces?
        return str;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    // Write new null terminator character
    end[1] = '\0';
    
    return str;
}

static int parse_config_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fd_log_error("Cannot open config file: %s", filename);
        return -1;
    }
    
    char line[512];
    char section[64] = "";
    
    while (fgets(line, sizeof(line), file)) {
        char* trimmed = trim_whitespace(line);
        
        // Skip empty lines and comments
        if (strlen(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        
        // Check for section headers [section]
        if (trimmed[0] == '[') {
            char* end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(section, trimmed + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }
        
        // Parse key=value pairs
        char* equal = strchr(trimmed, '=');
        if (!equal) continue;
        
        *equal = '\0';
        char* key = trim_whitespace(trimmed);
        char* value = trim_whitespace(equal + 1);
        
        // Remove quotes from value if present
        if (value[0] == '"' || value[0] == '\'') {
            value++;
            int len = strlen(value);
            if (len > 0 && (value[len-1] == '"' || value[len-1] == '\'')) {
                value[len-1] = '\0';
            }
        }
        
        // Parse vowifi section
        if (strcmp(section, "vowifi") == 0) {
            if (strcmp(key, "hss_host") == 0) {
                vowifiConfig.hssHost = (uint8_t*)strdup(value);
            } else if (strcmp(key, "hss_realm") == 0) {
                vowifiConfig.hssRealm = (uint8_t*)strdup(value);
            } else if (strcmp(key, "ldap_rest_url") == 0) {
                vowifiConfig.ldapRestUrl = (uint8_t*)strdup(value);
            } else if (strcmp(key, "session_id_suffix") == 0) {
                vowifiConfig.sessionIdSuffix = (os0_t)strdup(value);
                vowifiConfig.sessionIdSuffixLen = strlen(value);
            }
        }
        // Parse oracle section
        else if (strcmp(section, "oracle") == 0) {
            if (strcmp(key, "user") == 0) {
                vowifiConfig.db_user = strdup(value);
            } else if (strcmp(key, "password") == 0) {
                vowifiConfig.db_pass = strdup(value);
            } else if (strcmp(key, "connect") == 0) {
                vowifiConfig.db_conn = strdup(value);
            } else if (strcmp(key, "min_sessions") == 0) {
                vowifiConfig.db_minSessions = atoi(value);
            } else if (strcmp(key, "max_sessions") == 0) {
                vowifiConfig.db_maxSessions = atoi(value);
            } else if (strcmp(key, "session_incr") == 0) {
                vowifiConfig.db_sessionIncr = atoi(value);
            } else if (strcmp(key, "nowait") == 0) {
                vowifiConfig.db_nowait = atoi(value);
            } else if (strcmp(key, "car_server_ip") == 0) {
                vowifiConfig.car_server_ip = strdup(value);
            } else if(strcmp(key, "exp_res_code_ldap_missing") == 0) {
                vowifiConfig.exp_Res_code_ldap_missing = strdup(value);
            } else if(strcmp(key, "origin_host") == 0) {
                vowifiConfig.origin_host = strdup(value);
            }   
        }
    }
    
    fclose(file);
    return 0;
}

int loadConfigFromFile(char* conffile) {
    // Set default values first
    vowifiConfig.hssHost = (uint8_t*)strdup("gateway2.vowifi.local");
    vowifiConfig.hssRealm = (uint8_t*)strdup("vowifi.local");
    vowifiConfig.ldapRestUrl = (uint8_t*)strdup("http://cparuser:cparpass@localhost:8080/isvowifiaccess?imsi=%s");
    vowifiConfig.sessionIdSuffix = (os0_t)strdup("fd");
    vowifiConfig.sessionIdSuffixLen = strlen("fd");
    
    // Oracle default values
    vowifiConfig.db_user = getenv("ORACLE_USER") ? strdup(getenv("ORACLE_USER")) : strdup("webshop_user");
    vowifiConfig.db_pass = getenv("ORACLE_PASS") ? strdup(getenv("ORACLE_PASS")) : strdup("StrongPassword123");
    vowifiConfig.db_conn = getenv("ORACLE_CONNECT") ? strdup(getenv("ORACLE_CONNECT")) : strdup("//172.27.96.1:1521/xepdb1");
    vowifiConfig.db_minSessions = 1;
    vowifiConfig.db_maxSessions = 10;
    vowifiConfig.db_sessionIncr = 2;
    vowifiConfig.db_nowait = 1;
    vowifiConfig.car_server_ip = strdup("127.0.0.1"); // Default CAR server IP

    //ldap missing exp res code
    vowifiConfig.exp_Res_code_ldap_missing = strdup("5012"); // Default

    //origin_host
    vowifiConfig.origin_host = strdup("vowifi.local"); // Default
    
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
    
    return 0;
}

