#pragma once
#include "dpi.h"
#include <stdint.h>

/* Special constant to indicate that a field should be set to NULL */
#define ORACLE_SET_NULL "__SET_NULL__"

typedef struct {
    dpiContext *ctx;
    dpiPool    *pool;
} oracle_pool_t;

typedef struct {
    const char *user;         // pl. "webshop_user"
    const char *password;     // pl. "StrongPassword123"
    const char *connect;      // EZCONNECT: "//192.168.100.35:1521/xepdb1"
    uint32_t    minSessions;  // pl. 1
    uint32_t    maxSessions;  // pl. 8
    uint32_t    sessionIncr;  // pl. 1
    int         nowait;       // 0=WAIT, 1=NOWAIT
} oracle_pool_cfg_t;

typedef struct {
    char **rows;
    int row_count;
    int max_rows;
} query_result_t;

/* Query with return value */
query_result_t* oracle_query_get_result(const char *sql, int max_rows);
void oracle_free_result(query_result_t *result);


/* ===== THREAD-SAFE SINGLETON API ===== */
/* Thread-safe singleton pool initialization with reference counting */
int  oracle_pool_init_singleton(const oracle_pool_cfg_t *cfg);
void oracle_pool_fini_singleton(void);

/* Thread-safe connection acquire/release from singleton pool */
int  oracle_acquire_singleton(dpiConn **out);
void oracle_release_singleton(dpiConn *conn);

/* Check if singleton pool is initialized */
int  oracle_pool_is_initialized(void);

/* Get current reference count (for debugging) */
int  oracle_pool_get_ref_count(void);

/* Thread-safe query execution using singleton pool */
int  oracle_query_log_singleton(const char *sql, void (*logfn)(const char *));

/* ===== LEGACY API (maintained for compatibility) ===== */
int  oracle_pool_init(oracle_pool_t *op, const oracle_pool_cfg_t *cfg);
void oracle_pool_fini(oracle_pool_t *op);
int  oracle_acquire(oracle_pool_t *op, dpiConn **out);
void oracle_release(dpiConn *conn);
int  oracle_query_log(oracle_pool_t *op, dpiConn *conn, const char *sql, void (*logfn)(const char *));

/* ===== REJECTED_LOGONS TABLE OPERATIONS ===== */

/* Structure for rejected_logons table */
typedef struct {
    double id;                 // auto-generated (Oracle NUMBER as double)
    char session_id[101];      // VARCHAR2(100)
    char user_name[101];       // VARCHAR2(100) 
    char exp_res_code[101];    // VARCHAR2(100)
    char origin_host[101];     // VARCHAR2(100)
    char created_at[30];       // TIMESTAMP (formatted) - default SYSTIMESTAMP
    char car_server_ip[101];   // VARCHAR2(100)
} rejected_logon_t;

/* Insert new rejected logon record */
int oracle_insert_rejected_logon(const char *session_id, 
                                 const char *user_name,
                                 const char *exp_res_code,
                                 const char *origin_host,
                                 const char *car_server_ip);

/* Update rejected logon record by ID */
int oracle_update_rejected_logon(double id,
                                 const char *session_id,
                                 const char *user_name, 
                                 const char *exp_res_code,
                                 const char *origin_host,
                                 const char *car_server_ip);

/* Flexible update - only updates non-NULL fields */
/* Use ORACLE_SET_NULL constant to set a field to NULL */
int oracle_update_rejected_logon_fields(double id,
                                        const char *session_id,      // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                        const char *user_name,       // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                        const char *exp_res_code,    // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                        const char *origin_host,     // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                        const char *car_server_ip);  // NULL = don't update, ORACLE_SET_NULL = set to NULL

/* Query rejected logon records (with optional WHERE clause) */
/* Query rejected logon records (with optional WHERE clause) */
int oracle_query_rejected_logons(const char *where_clause, 
                                 rejected_logon_t **results,
                                 int *count,
                                 int max_results);

/* Free results from oracle_query_rejected_logons */
void oracle_free_rejected_logons(rejected_logon_t *results);

/* Get last error message */
const char* oracle_get_last_error(void);

/* ===== SESSION_LOGS TABLE OPERATIONS ===== */

/* Structure for session_logs table */
typedef struct {
    double id;                      // auto-generated (Oracle NUMBER as double)
    char session_id[101];           // VARCHAR2(100) NOT NULL
    char user_name[101];            // VARCHAR2(100) NOT NULL
    double origin_state_id;         // NUMBER (using 0 for NULL)
    char auth_request_type[51];     // VARCHAR2(50)
    char calling_station_id[101];   // VARCHAR2(100)
    char event_timestamp[30];       // TIMESTAMP (formatted) - default SYSTIMESTAMP
    char ip_address[46];            // VARCHAR2(45) - IPv4 or IPv6
    char msisdn[21];                // VARCHAR2(20) - phone number format
    char active;                    // CHAR(1) CHECK (active IN ('Y','N'))
    char service_selection[101];    // VARCHAR2(100)
    char start_timestamp[30];       // TIMESTAMP (formatted)
    char stop_timestamp[30];        // TIMESTAMP (formatted)
    char termination_cause[201];    // VARCHAR2(200)
    char car_server_ip[46];         // VARCHAR2(45)
    double update_count;            // NUMBER DEFAULT 0
} session_log_t;

/* Insert new session log record */
int oracle_insert_session_log(const char *session_id,
                              const char *user_name,
                              double origin_state_id,
                              const char *auth_request_type,
                              const char *calling_station_id,
                              const char *ip_address,
                              const char *msisdn,
                              char active,
                              const char *service_selection,
                              const char *start_timestamp,
                              const char *termination_cause,
                              const char *car_server_ip);

/* Update session log record by ID */
int oracle_update_session_log(double id,
                              const char *session_id,
                              const char *user_name,
                              double origin_state_id,
                              const char *auth_request_type,
                              const char *calling_station_id,
                              const char *ip_address,
                              const char *msisdn,
                              char active,
                              const char *service_selection,
                              const char *start_timestamp,
                              const char *stop_timestamp,
                              const char *termination_cause,
                              const char *car_server_ip);

/* Flexible update - only updates non-NULL fields */
/* Use ORACLE_SET_NULL constant to set string fields to NULL */
/* Use -1 for origin_state_id and update_count to indicate NULL */
/* Use '\0' for active char to indicate NULL */
int oracle_update_session_log_fields(double id,
                                     const char *session_id,        // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *user_name,         // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     double origin_state_id,        // -1 = don't update, -2 = set to NULL
                                     const char *auth_request_type, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *calling_station_id,// NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *ip_address,        // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *msisdn,            // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     char active,                   // '\0' = don't update, 'N' = set to NULL via special handling
                                     const char *service_selection, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *start_timestamp,   // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *stop_timestamp,    // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *termination_cause, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *car_server_ip);    // NULL = don't update, ORACLE_SET_NULL = set to NULL

/* Query session log records (with optional WHERE clause) */
int oracle_query_session_logs(const char *where_clause,
                              session_log_t **results,
                              int *count,
                              int max_results);

/* Free results from oracle_query_session_logs */
void oracle_free_session_logs(session_log_t *results);

/* ===== EGYSZERŰ PARAMÉTERES LEKÉRDEZÉS ===== */

/* Egyszerű paraméteres SELECT - egy paraméter, string eredmények */
int oracle_simple_query(const char *sql, const char *param_name, const char *param_value, char ***results, int *row_count);

/* Cleanup function for simple query results */
void oracle_free_simple_query(char **results, int row_count);

/* ===== PARAMETERIZED QUERY SUPPORT ===== */

/* Parameter types for parameterized queries */
typedef enum {
    ORACLE_PARAM_STRING = 0,
    ORACLE_PARAM_DOUBLE,
    ORACLE_PARAM_INT
} oracle_param_type_t;

/* Parameter structure for parameterized queries */
typedef struct {
    const char *name;          // Parameter name (e.g., "session_id")
    oracle_param_type_t type;  // Parameter type
    union {
        const char *str_val;   // String value
        double dbl_val;        // Double value  
        int int_val;           // Integer value
    } value;
} oracle_param_t;

/* Result structure for parameterized queries */
typedef struct {
    char **column_names;       // Array of column names
    char ***rows;              // Array of rows, each row is array of string values
    int column_count;          // Number of columns
    int row_count;             // Number of rows
    int max_rows;              // Maximum rows allocated
} oracle_query_result_t;

/* Execute parameterized SELECT query with binding support */
int oracle_query_parameterized(const char *sql, 
                               oracle_param_t *params, 
                               int param_count,
                               oracle_query_result_t **result,
                               int max_rows);

/* Free parameterized query result */
void oracle_free_query_result(oracle_query_result_t *result);

/* Helper functions for creating parameters */
oracle_param_t oracle_param_string(const char *name, const char *value);
oracle_param_t oracle_param_double(const char *name, double value);
oracle_param_t oracle_param_int(const char *name, int value);
