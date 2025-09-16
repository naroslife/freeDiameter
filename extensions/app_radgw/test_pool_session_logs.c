/*
 * Session Logs Table Operations for Oracle Database
 * Implementation of session_logs table CRUD operations
 */

#include "test_pool.h"
#include "dpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// External references from test_pool.c
extern struct {
    oracle_pool_t pool;
    int initialized;
    int ref_count;
    pthread_mutex_t mutex;
    char last_error[512];
} g_pool_singleton;

// Forward declarations of helper functions from test_pool.c
extern void set_last_error_with_context(const char *operation, const char *error);
extern void set_last_error(const char *error);

/* ===== SESSION_LOGS TABLE OPERATIONS ===== */

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
                              const char *car_server_ip) {
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("INSERT_SESSION_LOG", "Pool not initialized");
        return 0;
    }

    if (!session_id || !user_name) {
        set_last_error_with_context("INSERT_SESSION_LOG", "Required parameters (session_id, user_name) are NULL");
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return 0; // Error already set
    }

    dpiStmt *stmt = NULL;
    // SQL for session_logs table - event_timestamp has default SYSTIMESTAMP
    const char *sql = "INSERT INTO session_logs "
                     "(session_id, user_name, origin_state_id, auth_request_type, calling_station_id, "
                     "ip_address, msisdn, active, service_selection, start_timestamp, "
                     "termination_cause, car_server_ip) "
                     "VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12)";

    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Prepare statement
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT_SESSION_LOG prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create variables for binding (10 string vars + 1 double var + 1 char var)
    dpiVar *vars[12];
    dpiData *data[12];

    // Create string variables for string parameters (indexes 0,1,3,4,5,6,8,9,10,11)
    int string_indices[] = {0, 1, 3, 4, 5, 6, 8, 9, 10, 11};
    for (int i = 0; i < 10; i++) {
        int idx = string_indices[i];
        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES, 1, 4000, 1, 0, NULL, &vars[idx], &data[idx]) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("INSERT_SESSION_LOG create string var", err.message);
            // Release already created vars
            for (int j = 0; j < i; j++) {
                dpiVar_release(vars[string_indices[j]]);
            }
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Create double variable for origin_state_id (index 2)
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_NUMBER, DPI_NATIVE_TYPE_DOUBLE, 1, 0, 1, 0, NULL, &vars[2], &data[2]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT_SESSION_LOG create double var", err.message);
        // Release string vars
        for (int i = 0; i < 10; i++) {
            dpiVar_release(vars[string_indices[i]]);
        }
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create char variable for active (index 7)
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_CHAR, DPI_NATIVE_TYPE_BYTES, 1, 1, 1, 0, NULL, &vars[7], &data[7]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT_SESSION_LOG create char var", err.message);
        // Release other vars
        for (int i = 0; i < 10; i++) {
            dpiVar_release(vars[string_indices[i]]);
        }
        dpiVar_release(vars[2]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind parameters
    printf("DEBUG: Binding session_log parameters\n");

    // :1 - session_id (required)
    data[0]->isNull = 0;
    strncpy(data[0]->value.asBytes.ptr, session_id, 100);
    data[0]->value.asBytes.ptr[100] = '\0';
    data[0]->value.asBytes.length = strlen(data[0]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 1, vars[0]);

    // :2 - user_name (required)
    data[1]->isNull = 0;
    strncpy(data[1]->value.asBytes.ptr, user_name, 100);
    data[1]->value.asBytes.ptr[100] = '\0';
    data[1]->value.asBytes.length = strlen(data[1]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 2, vars[1]);

    // :3 - origin_state_id (double, can be 0 for NULL)
    if (origin_state_id == 0) {
        data[2]->isNull = 1;
    } else {
        data[2]->isNull = 0;
        data[2]->value.asDouble = origin_state_id;
    }
    dpiStmt_bindByPos(stmt, 3, vars[2]);

    // :4 - auth_request_type (optional)
    if (auth_request_type) {
        data[3]->isNull = 0;
        strncpy(data[3]->value.asBytes.ptr, auth_request_type, 50);
        data[3]->value.asBytes.ptr[50] = '\0';
        data[3]->value.asBytes.length = strlen(data[3]->value.asBytes.ptr);
    } else {
        data[3]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 4, vars[3]);

    // :5 - calling_station_id (optional)
    if (calling_station_id) {
        data[4]->isNull = 0;
        strncpy(data[4]->value.asBytes.ptr, calling_station_id, 100);
        data[4]->value.asBytes.ptr[100] = '\0';
        data[4]->value.asBytes.length = strlen(data[4]->value.asBytes.ptr);
    } else {
        data[4]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 5, vars[4]);

    // :6 - ip_address (optional)
    if (ip_address) {
        data[5]->isNull = 0;
        strncpy(data[5]->value.asBytes.ptr, ip_address, 45);
        data[5]->value.asBytes.ptr[45] = '\0';
        data[5]->value.asBytes.length = strlen(data[5]->value.asBytes.ptr);
    } else {
        data[5]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 6, vars[5]);

    // :7 - msisdn (optional)
    if (msisdn) {
        data[6]->isNull = 0;
        strncpy(data[6]->value.asBytes.ptr, msisdn, 20);
        data[6]->value.asBytes.ptr[20] = '\0';
        data[6]->value.asBytes.length = strlen(data[6]->value.asBytes.ptr);
    } else {
        data[6]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 7, vars[6]);

    // :8 - active (char, Y/N)
    if (active == 'Y' || active == 'N') {
        data[7]->isNull = 0;
        data[7]->value.asBytes.ptr[0] = active;
        data[7]->value.asBytes.length = 1;
    } else {
        data[7]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 8, vars[7]);

    // :9 - service_selection (optional)
    if (service_selection) {
        data[8]->isNull = 0;
        strncpy(data[8]->value.asBytes.ptr, service_selection, 100);
        data[8]->value.asBytes.ptr[100] = '\0';
        data[8]->value.asBytes.length = strlen(data[8]->value.asBytes.ptr);
    } else {
        data[8]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 9, vars[8]);

    // :10 - start_timestamp (optional)
    if (start_timestamp) {
        data[9]->isNull = 0;
        strncpy(data[9]->value.asBytes.ptr, start_timestamp, 29);
        data[9]->value.asBytes.ptr[29] = '\0';
        data[9]->value.asBytes.length = strlen(data[9]->value.asBytes.ptr);
    } else {
        data[9]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 10, vars[9]);

    // :11 - termination_cause (optional)
    if (termination_cause) {
        data[10]->isNull = 0;
        strncpy(data[10]->value.asBytes.ptr, termination_cause, 200);
        data[10]->value.asBytes.ptr[200] = '\0';
        data[10]->value.asBytes.length = strlen(data[10]->value.asBytes.ptr);
    } else {
        data[10]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 11, vars[10]);

    // :12 - car_server_ip (optional)
    if (car_server_ip) {
        data[11]->isNull = 0;
        strncpy(data[11]->value.asBytes.ptr, car_server_ip, 45);
        data[11]->value.asBytes.ptr[45] = '\0';
        data[11]->value.asBytes.length = strlen(data[11]->value.asBytes.ptr);
    } else {
        data[11]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 12, vars[11]);

    // Execute statement
    printf("DEBUG: About to execute INSERT session_log statement\n");
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT_SESSION_LOG execute", err.message);
        printf("DEBUG: INSERT session_log execute failed: %s\n", err.message);
        for (int i = 0; i < 12; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }
    printf("DEBUG: INSERT session_log statement executed successfully\n");

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT_SESSION_LOG commit", err.message);
        for (int i = 0; i < 12; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Cleanup
    for (int i = 0; i < 12; i++) {
        dpiVar_release(vars[i]);
    }
    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("INSERT_SESSION_LOG", "Success");
    return 1;
}

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
                              const char *car_server_ip) {
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("UPDATE_SESSION_LOG", "Pool not initialized");
        return 0;
    }

    if (!session_id || !user_name) {
        set_last_error_with_context("UPDATE_SESSION_LOG", "Required parameters (session_id, user_name) are NULL");
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return 0;
    }

    dpiStmt *stmt = NULL;
    const char *sql = "UPDATE session_logs SET "
                     "session_id = :1, user_name = :2, origin_state_id = :3, "
                     "auth_request_type = :4, calling_station_id = :5, ip_address = :6, "
                     "msisdn = :7, active = :8, service_selection = :9, "
                     "start_timestamp = :10, stop_timestamp = :11, termination_cause = :12, "
                     "car_server_ip = :13, update_count = update_count + 1 "
                     "WHERE id = :14";

    pthread_mutex_lock(&g_pool_singleton.mutex);

    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create variables for binding (11 string vars + 2 double vars + 1 char var)
    dpiVar *vars[14];
    dpiData *data[14];

    // Create string variables 
    int string_indices[] = {0, 1, 3, 4, 5, 6, 8, 9, 10, 11, 12};
    for (int i = 0; i < 11; i++) {
        int idx = string_indices[i];
        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES, 1, 4000, 1, 0, NULL, &vars[idx], &data[idx]) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("UPDATE_SESSION_LOG create string var", err.message);
            for (int j = 0; j < i; j++) {
                dpiVar_release(vars[string_indices[j]]);
            }
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Create double variables for origin_state_id (index 2) and id (index 13)
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_NUMBER, DPI_NATIVE_TYPE_DOUBLE, 1, 0, 1, 0, NULL, &vars[2], &data[2]) != DPI_SUCCESS ||
        dpiConn_newVar(conn, DPI_ORACLE_TYPE_NUMBER, DPI_NATIVE_TYPE_DOUBLE, 1, 0, 1, 0, NULL, &vars[13], &data[13]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG create double var", err.message);
        for (int i = 0; i < 11; i++) {
            dpiVar_release(vars[string_indices[i]]);
        }
        if (vars[2]) dpiVar_release(vars[2]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create char variable for active (index 7)
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_CHAR, DPI_NATIVE_TYPE_BYTES, 1, 1, 1, 0, NULL, &vars[7], &data[7]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG create char var", err.message);
        for (int i = 0; i < 11; i++) {
            dpiVar_release(vars[string_indices[i]]);
        }
        dpiVar_release(vars[2]);
        dpiVar_release(vars[13]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind all parameters (similar to insert but with additional stop_timestamp and id)
    // :1 - session_id
    data[0]->isNull = 0;
    strncpy(data[0]->value.asBytes.ptr, session_id, 100);
    data[0]->value.asBytes.ptr[100] = '\0';
    data[0]->value.asBytes.length = strlen(data[0]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 1, vars[0]);

    // :2 - user_name  
    data[1]->isNull = 0;
    strncpy(data[1]->value.asBytes.ptr, user_name, 100);
    data[1]->value.asBytes.ptr[100] = '\0';
    data[1]->value.asBytes.length = strlen(data[1]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 2, vars[1]);

    // :3 - origin_state_id
    if (origin_state_id == 0) {
        data[2]->isNull = 1;
    } else {
        data[2]->isNull = 0;
        data[2]->value.asDouble = origin_state_id;
    }
    dpiStmt_bindByPos(stmt, 3, vars[2]);

    // :4 - auth_request_type
    if (auth_request_type) {
        data[3]->isNull = 0;
        strncpy(data[3]->value.asBytes.ptr, auth_request_type, 50);
        data[3]->value.asBytes.ptr[50] = '\0';
        data[3]->value.asBytes.length = strlen(data[3]->value.asBytes.ptr);
    } else {
        data[3]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 4, vars[3]);

    // :5 - calling_station_id
    if (calling_station_id) {
        data[4]->isNull = 0;
        strncpy(data[4]->value.asBytes.ptr, calling_station_id, 100);
        data[4]->value.asBytes.ptr[100] = '\0';
        data[4]->value.asBytes.length = strlen(data[4]->value.asBytes.ptr);
    } else {
        data[4]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 5, vars[4]);

    // :6 - ip_address
    if (ip_address) {
        data[5]->isNull = 0;
        strncpy(data[5]->value.asBytes.ptr, ip_address, 45);
        data[5]->value.asBytes.ptr[45] = '\0';
        data[5]->value.asBytes.length = strlen(data[5]->value.asBytes.ptr);
    } else {
        data[5]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 6, vars[5]);

    // :7 - msisdn
    if (msisdn) {
        data[6]->isNull = 0;
        strncpy(data[6]->value.asBytes.ptr, msisdn, 20);
        data[6]->value.asBytes.ptr[20] = '\0';
        data[6]->value.asBytes.length = strlen(data[6]->value.asBytes.ptr);
    } else {
        data[6]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 7, vars[6]);

    // :8 - active
    if (active == 'Y' || active == 'N') {
        data[7]->isNull = 0;
        data[7]->value.asBytes.ptr[0] = active;
        data[7]->value.asBytes.length = 1;
    } else {
        data[7]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 8, vars[7]);

    // :9 - service_selection
    if (service_selection) {
        data[8]->isNull = 0;
        strncpy(data[8]->value.asBytes.ptr, service_selection, 100);
        data[8]->value.asBytes.ptr[100] = '\0';
        data[8]->value.asBytes.length = strlen(data[8]->value.asBytes.ptr);
    } else {
        data[8]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 9, vars[8]);

    // :10 - start_timestamp
    if (start_timestamp) {
        data[9]->isNull = 0;
        strncpy(data[9]->value.asBytes.ptr, start_timestamp, 29);
        data[9]->value.asBytes.ptr[29] = '\0';
        data[9]->value.asBytes.length = strlen(data[9]->value.asBytes.ptr);
    } else {
        data[9]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 10, vars[9]);

    // :11 - stop_timestamp
    if (stop_timestamp) {
        data[10]->isNull = 0;
        strncpy(data[10]->value.asBytes.ptr, stop_timestamp, 29);
        data[10]->value.asBytes.ptr[29] = '\0';
        data[10]->value.asBytes.length = strlen(data[10]->value.asBytes.ptr);
    } else {
        data[10]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 11, vars[10]);

    // :12 - termination_cause
    if (termination_cause) {
        data[11]->isNull = 0;
        strncpy(data[11]->value.asBytes.ptr, termination_cause, 200);
        data[11]->value.asBytes.ptr[200] = '\0';
        data[11]->value.asBytes.length = strlen(data[11]->value.asBytes.ptr);
    } else {
        data[11]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 12, vars[11]);

    // :13 - car_server_ip
    if (car_server_ip) {
        data[12]->isNull = 0;
        strncpy(data[12]->value.asBytes.ptr, car_server_ip, 45);
        data[12]->value.asBytes.ptr[45] = '\0';
        data[12]->value.asBytes.length = strlen(data[12]->value.asBytes.ptr);
    } else {
        data[12]->isNull = 1;
    }
    dpiStmt_bindByPos(stmt, 13, vars[12]);

    // :14 - id (WHERE clause)
    data[13]->isNull = 0;
    data[13]->value.asDouble = id;
    dpiStmt_bindByPos(stmt, 14, vars[13]);

    // Execute statement
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG execute", err.message);
        for (int i = 0; i < 14; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Check how many rows were affected
    uint64_t rowCount = 0;
    if (dpiStmt_getRowCount(stmt, &rowCount) == DPI_SUCCESS) {
        printf("[UPDATE_SESSION_LOG] Rows affected: %lu\n", (unsigned long)rowCount);
        if (rowCount == 0) {
            printf("[UPDATE_SESSION_LOG] Warning: No rows were updated (ID %.0f not found)\n", id);
        }
    }

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG commit", err.message);
        for (int i = 0; i < 14; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Cleanup
    for (int i = 0; i < 14; i++) {
        dpiVar_release(vars[i]);
    }
    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("UPDATE_SESSION_LOG", "Success");
    return 1;
}

/* Flexible update - only updates non-NULL fields */
int oracle_update_session_log_fields(double id,
                                     const char *session_id,        // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *user_name,         // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     double origin_state_id,        // -1 = don't update, -2 = set to NULL
                                     const char *auth_request_type, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *calling_station_id,// NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *ip_address,        // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *msisdn,            // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     char active,                   // '\0' = don't update, 'X' = set to NULL via special handling
                                     const char *service_selection, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *start_timestamp,   // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *stop_timestamp,    // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *termination_cause, // NULL = don't update, ORACLE_SET_NULL = set to NULL
                                     const char *car_server_ip) {   // NULL = don't update, ORACLE_SET_NULL = set to NULL
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS", "Pool not initialized");
        return 0;
    }

    // Build dynamic SQL based on provided fields
    char sql[2048] = "UPDATE session_logs SET ";
    int field_count = 0;
    int first_field = 1;

    // Check each field and add to SQL if provided
    if (session_id != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "session_id = :session_id");
        field_count++;
        first_field = 0;
    }

    if (user_name != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "user_name = :user_name");
        field_count++;
        first_field = 0;
    }

    if (origin_state_id != -1) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "origin_state_id = :origin_state_id");
        field_count++;
        first_field = 0;
    }

    if (auth_request_type != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "auth_request_type = :auth_request_type");
        field_count++;
        first_field = 0;
    }

    if (calling_station_id != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "calling_station_id = :calling_station_id");
        field_count++;
        first_field = 0;
    }

    if (ip_address != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "ip_address = :ip_address");
        field_count++;
        first_field = 0;
    }

    if (msisdn != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "msisdn = :msisdn");
        field_count++;
        first_field = 0;
    }

    if (active != '\0') {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "active = :active");
        field_count++;
        first_field = 0;
    }

    if (service_selection != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "service_selection = :service_selection");
        field_count++;
        first_field = 0;
    }

    if (start_timestamp != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "start_timestamp = :start_timestamp");
        field_count++;
        first_field = 0;
    }

    if (stop_timestamp != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "stop_timestamp = :stop_timestamp");
        field_count++;
        first_field = 0;
    }

    if (termination_cause != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "termination_cause = :termination_cause");
        field_count++;
        first_field = 0;
    }

    if (car_server_ip != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "car_server_ip = :car_server_ip");
        field_count++;
        first_field = 0;
    }

    if (field_count == 0) {
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS", "No fields to update");
        return 0;
    }

    // Always increment update_count
    if (!first_field) strcat(sql, ", ");
    strcat(sql, "update_count = update_count + 1");

    strcat(sql, " WHERE id = :id");

    printf("DEBUG: Dynamic session_log SQL: %s\n", sql);

    dpiConn *conn = NULL;
    pthread_mutex_lock(&g_pool_singleton.mutex);

    if (!oracle_acquire_singleton(&conn)) {
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS", "Failed to acquire connection");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    dpiStmt *stmt = NULL;
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind ID parameter (always present)
    if (dpiStmt_bindValueByName(stmt, "id", 2, DPI_NATIVE_TYPE_DOUBLE, &id) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS bind id", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind optional parameters using consistent approach
    if (session_id != NULL) {
        dpiData data;
        if (strcmp(session_id, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)session_id;
            data.value.asBytes.length = strlen(session_id);
        }
        dpiStmt_bindValueByName(stmt, "session_id", 10, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (user_name != NULL) {
        dpiData data;
        if (strcmp(user_name, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)user_name;
            data.value.asBytes.length = strlen(user_name);
        }
        dpiStmt_bindValueByName(stmt, "user_name", 9, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (origin_state_id != -1) {
        dpiData data;
        if (origin_state_id == -2) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asDouble = origin_state_id;
        }
        dpiStmt_bindValueByName(stmt, "origin_state_id", 15, DPI_NATIVE_TYPE_DOUBLE, &data);
    }

    if (auth_request_type != NULL) {
        dpiData data;
        if (strcmp(auth_request_type, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)auth_request_type;
            data.value.asBytes.length = strlen(auth_request_type);
        }
        dpiStmt_bindValueByName(stmt, "auth_request_type", 17, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (calling_station_id != NULL) {
        dpiData data;
        if (strcmp(calling_station_id, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)calling_station_id;
            data.value.asBytes.length = strlen(calling_station_id);
        }
        dpiStmt_bindValueByName(stmt, "calling_station_id", 18, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (ip_address != NULL) {
        dpiData data;
        if (strcmp(ip_address, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)ip_address;
            data.value.asBytes.length = strlen(ip_address);
        }
        dpiStmt_bindValueByName(stmt, "ip_address", 10, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (msisdn != NULL) {
        dpiData data;
        if (strcmp(msisdn, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)msisdn;
            data.value.asBytes.length = strlen(msisdn);
        }
        dpiStmt_bindValueByName(stmt, "msisdn", 6, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (active != '\0') {
        dpiData data;
        if (active == 'X') { // Special value to indicate NULL
            data.isNull = 1;
        } else {
            data.isNull = 0;
            char active_str[2] = {active, '\0'};
            data.value.asBytes.ptr = active_str;
            data.value.asBytes.length = 1;
        }
        dpiStmt_bindValueByName(stmt, "active", 6, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (service_selection != NULL) {
        dpiData data;
        if (strcmp(service_selection, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)service_selection;
            data.value.asBytes.length = strlen(service_selection);
        }
        dpiStmt_bindValueByName(stmt, "service_selection", 17, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (start_timestamp != NULL) {
        dpiData data;
        if (strcmp(start_timestamp, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)start_timestamp;
            data.value.asBytes.length = strlen(start_timestamp);
        }
        dpiStmt_bindValueByName(stmt, "start_timestamp", 15, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (stop_timestamp != NULL) {
        dpiData data;
        if (strcmp(stop_timestamp, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)stop_timestamp;
            data.value.asBytes.length = strlen(stop_timestamp);
        }
        dpiStmt_bindValueByName(stmt, "stop_timestamp", 14, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (termination_cause != NULL) {
        dpiData data;
        if (strcmp(termination_cause, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)termination_cause;
            data.value.asBytes.length = strlen(termination_cause);
        }
        dpiStmt_bindValueByName(stmt, "termination_cause", 17, DPI_NATIVE_TYPE_BYTES, &data);
    }

    if (car_server_ip != NULL) {
        dpiData data;
        if (strcmp(car_server_ip, ORACLE_SET_NULL) == 0) {
            data.isNull = 1;
        } else {
            data.isNull = 0;
            data.value.asBytes.ptr = (char*)car_server_ip;
            data.value.asBytes.length = strlen(car_server_ip);
        }
        dpiStmt_bindValueByName(stmt, "car_server_ip", 13, DPI_NATIVE_TYPE_BYTES, &data);
    }

    // Execute the update
    uint32_t numQueryColumns = 0;
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, &numQueryColumns) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS execute", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Get row count
    uint64_t rowCount = 0;
    dpiStmt_getRowCount(stmt, &rowCount);
    printf("DEBUG: Flexible session_log update affected %lu rows\n", (unsigned long)rowCount);

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS commit", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS", "Success");
    return 1;
}

/* Query session log records (with optional WHERE clause) */
int oracle_query_session_logs(const char *where_clause,
                              session_log_t **results,
                              int *count,
                              int max_results) {
    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Initialize output parameters
    if (results) *results = NULL;
    if (count) *count = 0;

    if (!g_pool_singleton.initialized) {
        set_last_error("Pool not initialized");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        set_last_error("Failed to acquire connection");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    // Build SQL query
    char sql[1024];
    if (where_clause && strlen(where_clause) > 0) {
        snprintf(sql, sizeof(sql),
            "SELECT id, session_id, user_name, origin_state_id, auth_request_type, "
            "calling_station_id, TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp, "
            "ip_address, msisdn, active, service_selection, "
            "TO_CHAR(start_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS start_timestamp, "
            "TO_CHAR(stop_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS stop_timestamp, "
            "termination_cause, car_server_ip, update_count "
            "FROM session_logs WHERE %s ORDER BY id DESC",
            where_clause);
    } else {
        snprintf(sql, sizeof(sql),
            "SELECT id, session_id, user_name, origin_state_id, auth_request_type, "
            "calling_station_id, TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS event_timestamp, "
            "ip_address, msisdn, active, service_selection, "
            "TO_CHAR(start_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS start_timestamp, "
            "TO_CHAR(stop_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS stop_timestamp, "
            "termination_cause, car_server_ip, update_count "
            "FROM session_logs ORDER BY id DESC");
    }

    // Add row limit if specified
    if (max_results > 0) {
        char limited_sql[1500];
        snprintf(limited_sql, sizeof(limited_sql),
            "SELECT * FROM (%s) WHERE ROWNUM <= %d", sql, max_results);
        strcpy(sql, limited_sql);
    }

    dpiStmt *stmt = NULL;
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("QUERY_SESSION_LOGS prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("QUERY_SESSION_LOGS execute", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Allocate temporary array to store results
    session_log_t *temp_results = malloc(max_results > 0 ? max_results * sizeof(session_log_t) : 1000 * sizeof(session_log_t));
    if (!temp_results) {
        set_last_error("Memory allocation failed for session_logs query results");
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    int row_count = 0;
    int max_alloc = max_results > 0 ? max_results : 1000;

    // Fetch rows
    int found = 0;
    uint32_t bufferRowIndex = 0;

    while (dpiStmt_fetch(stmt, &found, &bufferRowIndex) == DPI_SUCCESS && found) {
        if (row_count >= max_alloc) {
            break;
        }

        session_log_t *current = &temp_results[row_count];
        memset(current, 0, sizeof(session_log_t));

        // Get column data
        dpiData *data = NULL;
        dpiNativeTypeNum nativeTypeNum = 0;

        // Column 1: id (NUMBER -> double)
        if (dpiStmt_getQueryValue(stmt, 1, &nativeTypeNum, &data) == DPI_SUCCESS && data) {
            if (nativeTypeNum == DPI_NATIVE_TYPE_DOUBLE) {
                current->id = data->value.asDouble;
            } else if (nativeTypeNum == DPI_NATIVE_TYPE_INT64) {
                current->id = (double)data->value.asInt64;
            }
        }

        // Column 2: session_id (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 2, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->session_id)) len = sizeof(current->session_id) - 1;
            memcpy(current->session_id, data->value.asBytes.ptr, len);
            current->session_id[len] = '\0';
        }

        // Column 3: user_name (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 3, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->user_name)) len = sizeof(current->user_name) - 1;
            memcpy(current->user_name, data->value.asBytes.ptr, len);
            current->user_name[len] = '\0';
        }

        // Column 4: origin_state_id (NUMBER -> double)
        if (dpiStmt_getQueryValue(stmt, 4, &nativeTypeNum, &data) == DPI_SUCCESS && data && !data->isNull) {
            if (nativeTypeNum == DPI_NATIVE_TYPE_DOUBLE) {
                current->origin_state_id = data->value.asDouble;
            } else if (nativeTypeNum == DPI_NATIVE_TYPE_INT64) {
                current->origin_state_id = (double)data->value.asInt64;
            }
        }

        // Column 5: auth_request_type (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 5, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->auth_request_type)) len = sizeof(current->auth_request_type) - 1;
            memcpy(current->auth_request_type, data->value.asBytes.ptr, len);
            current->auth_request_type[len] = '\0';
        }

        // Column 6: calling_station_id (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 6, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->calling_station_id)) len = sizeof(current->calling_station_id) - 1;
            memcpy(current->calling_station_id, data->value.asBytes.ptr, len);
            current->calling_station_id[len] = '\0';
        }

        // Column 7: event_timestamp (formatted TIMESTAMP)
        if (dpiStmt_getQueryValue(stmt, 7, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->event_timestamp)) len = sizeof(current->event_timestamp) - 1;
            memcpy(current->event_timestamp, data->value.asBytes.ptr, len);
            current->event_timestamp[len] = '\0';
        }

        // Column 8: ip_address (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 8, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->ip_address)) len = sizeof(current->ip_address) - 1;
            memcpy(current->ip_address, data->value.asBytes.ptr, len);
            current->ip_address[len] = '\0';
        }

        // Column 9: msisdn (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 9, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->msisdn)) len = sizeof(current->msisdn) - 1;
            memcpy(current->msisdn, data->value.asBytes.ptr, len);
            current->msisdn[len] = '\0';
        }

        // Column 10: active (CHAR)
        if (dpiStmt_getQueryValue(stmt, 10, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            current->active = data->value.asBytes.ptr[0];
        }

        // Column 11: service_selection (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 11, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->service_selection)) len = sizeof(current->service_selection) - 1;
            memcpy(current->service_selection, data->value.asBytes.ptr, len);
            current->service_selection[len] = '\0';
        }

        // Column 12: start_timestamp (formatted TIMESTAMP)
        if (dpiStmt_getQueryValue(stmt, 12, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->start_timestamp)) len = sizeof(current->start_timestamp) - 1;
            memcpy(current->start_timestamp, data->value.asBytes.ptr, len);
            current->start_timestamp[len] = '\0';
        }

        // Column 13: stop_timestamp (formatted TIMESTAMP)
        if (dpiStmt_getQueryValue(stmt, 13, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->stop_timestamp)) len = sizeof(current->stop_timestamp) - 1;
            memcpy(current->stop_timestamp, data->value.asBytes.ptr, len);
            current->stop_timestamp[len] = '\0';
        }

        // Column 14: termination_cause (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 14, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->termination_cause)) len = sizeof(current->termination_cause) - 1;
            memcpy(current->termination_cause, data->value.asBytes.ptr, len);
            current->termination_cause[len] = '\0';
        }

        // Column 15: car_server_ip (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 15, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->car_server_ip)) len = sizeof(current->car_server_ip) - 1;
            memcpy(current->car_server_ip, data->value.asBytes.ptr, len);
            current->car_server_ip[len] = '\0';
        }

        // Column 16: update_count (NUMBER -> double)
        if (dpiStmt_getQueryValue(stmt, 16, &nativeTypeNum, &data) == DPI_SUCCESS && data && !data->isNull) {
            if (nativeTypeNum == DPI_NATIVE_TYPE_DOUBLE) {
                current->update_count = data->value.asDouble;
            } else if (nativeTypeNum == DPI_NATIVE_TYPE_INT64) {
                current->update_count = (double)data->value.asInt64;
            }
        }

        row_count++;
    }

    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    // Set output parameters
    if (results) {
        *results = temp_results;
    } else {
        free(temp_results);
    }
    if (count) {
        *count = row_count;
    }

    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), "Session logs query completed successfully, returned %d rows", row_count);
    set_last_error(debug_msg);

    return 1; // Success
}

/* Free results from oracle_query_session_logs */
void oracle_free_session_logs(session_log_t *results) {
    if (results) {
        free(results);
    }
}
