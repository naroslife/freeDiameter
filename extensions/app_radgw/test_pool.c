#include "test_pool.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

/* ===== THREAD-SAFE SINGLETON POOL MANAGER ===== */
static struct {
    oracle_pool_t pool;
    pthread_mutex_t mutex;
    int initialized;
    int ref_count;
    char last_error[512];
} g_pool_singleton = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .initialized = 0,
    .ref_count = 0,
    .last_error = {0}
};

/* Static variable for query result collection */
static query_result_t *current_result = NULL;

static void set_last_error(const char *error) {
    snprintf(g_pool_singleton.last_error, sizeof(g_pool_singleton.last_error), "%s", error);
}

static void print_last_error(dpiContext *ctx, const char *where, void (*logfn)(const char*)) {
    dpiErrorInfo err;
    dpiContext_getError(ctx, &err);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s: %.*s", where, err.messageLength, err.message);
    if (n > 0 && logfn) logfn(buf);
}

int oracle_pool_init(oracle_pool_t *op, const oracle_pool_cfg_t *cfg) {
    memset(op, 0, sizeof *op);
    dpiErrorInfo err;
    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION, &op->ctx, &err) != DPI_SUCCESS) {
        fprintf(stderr, "dpiContext_create: %.*s\n", err.messageLength, err.message);
        return 0;
    }

    dpiCommonCreateParams cpar;
    dpiPoolCreateParams   ppar;
    dpiContext_initCommonCreateParams(op->ctx, &cpar);
    dpiContext_initPoolCreateParams(op->ctx, &ppar);
    cpar.encoding  = "UTF-8";
    cpar.nencoding = "UTF-8";

    ppar.minSessions      = cfg->minSessions ? cfg->minSessions : 1;
    ppar.maxSessions      = cfg->maxSessions ? cfg->maxSessions : 8;
    ppar.sessionIncrement = cfg->sessionIncr ? cfg->sessionIncr : 1;
    ppar.homogeneous      = 1; /* user/pass a poolon */
    ppar.getMode          = cfg->nowait ? DPI_MODE_POOL_GET_NOWAIT : DPI_MODE_POOL_GET_WAIT;

    if (dpiPool_create(op->ctx,
        (const char*)cfg->user,    (uint32_t)strlen(cfg->user),
        (const char*)cfg->password,(uint32_t)strlen(cfg->password),
        (const char*)cfg->connect, (uint32_t)strlen(cfg->connect),
        &cpar, &ppar, &op->pool) != DPI_SUCCESS) {
        print_last_error(op->ctx, "dpiPool_create", NULL);
        dpiContext_destroy(op->ctx); op->ctx = NULL;
        return 0;
    }
    return 1;
}

void oracle_pool_fini(oracle_pool_t *op) {
    if (!op) return;
    if (op->pool)  { dpiPool_release(op->pool); op->pool = NULL; }
    if (op->ctx)   { dpiContext_destroy(op->ctx); op->ctx = NULL; }
}

int oracle_acquire(oracle_pool_t *op, dpiConn **out) {
    if (!op || !op->pool) return 0;
    if (dpiPool_acquireConnection(op->pool, NULL, 0, NULL, 0, NULL, out) != DPI_SUCCESS) {
        print_last_error(op->ctx, "dpiPool_acquireConnection", NULL);
        return 0;
    }
    return 1;
}

void oracle_release(dpiConn *conn) {
    if (conn) dpiConn_release(conn);
}

/* egyszerű logger callback helyett alapból stderr-re írunk, ha nincs handler */
static void default_log(const char *s) { fprintf(stderr, "%s\n", s); }

/* Hibakezelő függvény context nélkül - próbáljuk meg a connection-ből kinyerni */
static void print_connection_error(dpiConn *conn, const char *where, void (*logfn)(const char*)) {
    if (!logfn) logfn = default_log;

    // Próbáljuk meg az Oracle hibakódot megszerezni a kapcsolaton keresztül
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s failed - Oracle error details not available without context", where);
    logfn(buf);
}

int oracle_query_log(oracle_pool_t *op, dpiConn *conn, const char *sql, void (*logfn)(const char *)) {
    if (!logfn) logfn = default_log;
    dpiStmt *stmt = NULL;

    logfn("Preparing statement...");
    if (dpiConn_prepareStmt(conn, 0, sql, (uint32_t)strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        print_last_error(op ? op->ctx : NULL, "dpiConn_prepareStmt", logfn);
        return 0;
    }

    logfn("Executing statement...");
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        print_last_error(op ? op->ctx : NULL, "dpiStmt_execute", logfn);
        dpiStmt_release(stmt);
        return 0;
    }

    logfn("Getting column count...");
    uint32_t cols=0;
    if (dpiStmt_getNumQueryColumns(stmt, &cols) != DPI_SUCCESS) {
        print_last_error(op ? op->ctx : NULL, "dpiStmt_getNumQueryColumns", logfn);
        dpiStmt_release(stmt);
        return 0;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "Found %u columns", cols);
    logfn(buf);

    int found=0;
    logfn("Starting fetch loop...");
    while (1) {
        uint32_t bufferRowIndex = 0;  // Ez nem lehet NULL!
        if (dpiStmt_fetch(stmt, &found, &bufferRowIndex) != DPI_SUCCESS) {
            print_last_error(op ? op->ctx : NULL, "dpiStmt_fetch", logfn);
            break;
        }
        if (!found) {
            logfn("No more rows found");
            break;
        }
        logfn("Processing row...");
        for (uint32_t c=1;c<=cols;c++){
            dpiNativeTypeNum t; dpiData *d;
            if (dpiStmt_getQueryValue(stmt, c, &t, &d) != DPI_SUCCESS) {
                print_last_error(op ? op->ctx : NULL, "dpiStmt_getQueryValue", logfn);
                dpiStmt_release(stmt);
                return 0;
            }
            char line[1024]; line[0]='\0';
            if (d->isNull) snprintf(line, sizeof line, "  NULL");
            else if (t==DPI_NATIVE_TYPE_BYTES) snprintf(line, sizeof line, "  %.*s", d->value.asBytes.length, (const char*)d->value.asBytes.ptr);
            else if (t==DPI_NATIVE_TYPE_INT64) snprintf(line, sizeof line, "  %lld", (long long)d->value.asInt64);
            else snprintf(line, sizeof line, "  <type:%d>", (int)t);
            logfn(line);
        }
    }
    dpiStmt_release(stmt);
    return 1;
}

/* ===== THREAD-SAFE SINGLETON API ===== */

int oracle_pool_init_singleton(const oracle_pool_cfg_t *cfg) {
    if (!cfg) {
        set_last_error("Configuration is NULL");
        return 0;
    }

    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Ha már inicializálva van, csak növeljük a reference count-ot
    if (g_pool_singleton.initialized) {
        g_pool_singleton.ref_count++;
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 1;
    }

    // Első inicializálás
    memset(&g_pool_singleton.pool, 0, sizeof(g_pool_singleton.pool));

    dpiErrorInfo err;
    if (dpiContext_create(DPI_MAJOR_VERSION, DPI_MINOR_VERSION,
                         &g_pool_singleton.pool.ctx, &err) != DPI_SUCCESS) {
        snprintf(g_pool_singleton.last_error, sizeof(g_pool_singleton.last_error),
                "dpiContext_create: %.*s", err.messageLength, err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    dpiCommonCreateParams cpar;
    dpiPoolCreateParams   ppar;
    dpiContext_initCommonCreateParams(g_pool_singleton.pool.ctx, &cpar);
    dpiContext_initPoolCreateParams(g_pool_singleton.pool.ctx, &ppar);
    cpar.encoding  = "UTF-8";
    cpar.nencoding = "UTF-8";

    ppar.minSessions      = cfg->minSessions ? cfg->minSessions : 1;
    ppar.maxSessions      = cfg->maxSessions ? cfg->maxSessions : 8;
    ppar.sessionIncrement = cfg->sessionIncr ? cfg->sessionIncr : 1;
    ppar.homogeneous      = 1;
    ppar.getMode          = cfg->nowait ? DPI_MODE_POOL_GET_NOWAIT : DPI_MODE_POOL_GET_WAIT;

    if (dpiPool_create(g_pool_singleton.pool.ctx,
        (const char*)cfg->user,    (uint32_t)strlen(cfg->user),
        (const char*)cfg->password,(uint32_t)strlen(cfg->password),
        (const char*)cfg->connect, (uint32_t)strlen(cfg->connect),
        &cpar, &ppar, &g_pool_singleton.pool.pool) != DPI_SUCCESS) {

        dpiErrorInfo pool_err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &pool_err);
        snprintf(g_pool_singleton.last_error, sizeof(g_pool_singleton.last_error),
                "dpiPool_create: %.*s", pool_err.messageLength, pool_err.message);

        dpiContext_destroy(g_pool_singleton.pool.ctx);
        g_pool_singleton.pool.ctx = NULL;
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    g_pool_singleton.initialized = 1;
    g_pool_singleton.ref_count = 1;
    set_last_error("Pool initialized successfully");
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    return 1;
}

void oracle_pool_fini_singleton(void) {
    pthread_mutex_lock(&g_pool_singleton.mutex);

    if (!g_pool_singleton.initialized) {
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return;
    }

    g_pool_singleton.ref_count--;

    // Csak akkor szabadítjuk fel a pool-t, ha nincs több referencia
    if (g_pool_singleton.ref_count <= 0) {
        if (g_pool_singleton.pool.pool) {
            dpiPool_release(g_pool_singleton.pool.pool);
            g_pool_singleton.pool.pool = NULL;
        }
        if (g_pool_singleton.pool.ctx) {
            dpiContext_destroy(g_pool_singleton.pool.ctx);
            g_pool_singleton.pool.ctx = NULL;
        }
        g_pool_singleton.initialized = 0;
        g_pool_singleton.ref_count = 0;
        set_last_error("Pool finalized");
    }

    pthread_mutex_unlock(&g_pool_singleton.mutex);
}

int oracle_acquire_singleton(dpiConn **out) {
    if (!out) {
        set_last_error("Output connection pointer is NULL");
        return 0;
    }

    pthread_mutex_lock(&g_pool_singleton.mutex);

    if (!g_pool_singleton.initialized || !g_pool_singleton.pool.pool) {
        set_last_error("Pool not initialized");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    // ODPI-C pool acquire (pool itself is thread-safe)
    int result = (dpiPool_acquireConnection(g_pool_singleton.pool.pool,
                                          NULL, 0, NULL, 0, NULL, out) == DPI_SUCCESS);

    if (!result) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        snprintf(g_pool_singleton.last_error, sizeof(g_pool_singleton.last_error),
                "dpiPool_acquireConnection: %.*s", err.messageLength, err.message);
    } else {
        set_last_error("Connection acquired successfully");
    }

    pthread_mutex_unlock(&g_pool_singleton.mutex);
    return result;
}

void oracle_release_singleton(dpiConn *conn) {
    if (conn) {
        dpiConn_release(conn);
    }
}

int oracle_pool_is_initialized(void) {
    pthread_mutex_lock(&g_pool_singleton.mutex);
    int initialized = g_pool_singleton.initialized;
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    return initialized;
}

int oracle_pool_get_ref_count(void) {
    pthread_mutex_lock(&g_pool_singleton.mutex);
    int ref_count = g_pool_singleton.ref_count;
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    return ref_count;
}

int oracle_query_log_singleton(const char *sql, void (*logfn)(const char *)) {
    if (!sql) {
        set_last_error("SQL is NULL");
        return 0;
    }

    if (!oracle_pool_is_initialized()) {
        set_last_error("Pool not initialized");
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return 0; // Error already set by acquire
    }

    // Use the existing oracle_query_log with singleton pool
    pthread_mutex_lock(&g_pool_singleton.mutex);
    int result = oracle_query_log(&g_pool_singleton.pool, conn, sql, logfn);
    pthread_mutex_unlock(&g_pool_singleton.mutex);

    oracle_release_singleton(conn);
    return result;
}

/* ===== REJECTED_LOGONS TABLE OPERATIONS ===== */

static void set_last_error_with_context(const char *operation, const char *error) {
    snprintf(g_pool_singleton.last_error, sizeof(g_pool_singleton.last_error),
             "%s: %s", operation, error);
}

int oracle_insert_rejected_logon(const char *session_id,
                                 const char *user_name,
                                 const char *exp_res_code,
                                 const char *origin_host,
                                 const char *car_server_ip) {
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("INSERT", "Pool not initialized");
        return 0;
    }

    if (!session_id || !user_name || !exp_res_code || !origin_host || !car_server_ip) {
        set_last_error_with_context("INSERT", "NULL parameter provided");
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return 0; // Error already set
    }

    dpiStmt *stmt = NULL;
    // Updated SQL for new table structure - created_at has default SYSTIMESTAMP
    const char *sql = "INSERT INTO rejected_logons "
                     "(session_id, user_name, exp_res_code, origin_host, car_server_ip) "
                     "VALUES (:1, :2, :3, :4, :5)";

    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Prepare statement
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create variables for binding
    dpiVar *vars[5];
    dpiData *data[5];

    // Create string variables for all parameters
    for (int i = 0; i < 5; i++) {
        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES, 1, 4000, 1, 0, NULL, &vars[i], &data[i]) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("CREATE var", err.message);
            // Release already created vars
            for (int j = 0; j < i; j++) {
                dpiVar_release(vars[j]);
            }
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Bind parameters
    printf("DEBUG: Binding parameters: session_id='%s', user_name='%s', exp_res_code='%s', origin_host='%s', car_server_ip='%s'\n",
           session_id, user_name, exp_res_code, origin_host, car_server_ip);

    // :1 - session_id
    data[0]->isNull = 0;
    strncpy(data[0]->value.asBytes.ptr, session_id, 3999);
    data[0]->value.asBytes.ptr[3999] = '\0';
    data[0]->value.asBytes.length = strlen(data[0]->value.asBytes.ptr);
    if (dpiStmt_bindByPos(stmt, 1, vars[0]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT bind session_id", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // :2 - user_name
    data[1]->isNull = 0;
    strncpy(data[1]->value.asBytes.ptr, user_name, 3999);
    data[1]->value.asBytes.ptr[3999] = '\0';
    data[1]->value.asBytes.length = strlen(data[1]->value.asBytes.ptr);
    if (dpiStmt_bindByPos(stmt, 2, vars[1]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT bind user_name", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // :3 - exp_res_code
    data[2]->isNull = 0;
    strncpy(data[2]->value.asBytes.ptr, exp_res_code, 3999);
    data[2]->value.asBytes.ptr[3999] = '\0';
    data[2]->value.asBytes.length = strlen(data[2]->value.asBytes.ptr);
    if (dpiStmt_bindByPos(stmt, 3, vars[2]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT bind exp_res_code", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // :4 - origin_host
    data[3]->isNull = 0;
    strncpy(data[3]->value.asBytes.ptr, origin_host, 3999);
    data[3]->value.asBytes.ptr[3999] = '\0';
    data[3]->value.asBytes.length = strlen(data[3]->value.asBytes.ptr);
    if (dpiStmt_bindByPos(stmt, 4, vars[3]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT bind origin_host", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // :5 - car_server_ip
    data[4]->isNull = 0;
    strncpy(data[4]->value.asBytes.ptr, car_server_ip, 3999);
    data[4]->value.asBytes.ptr[3999] = '\0';
    data[4]->value.asBytes.length = strlen(data[4]->value.asBytes.ptr);
    if (dpiStmt_bindByPos(stmt, 5, vars[4]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT bind car_server_ip", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Execute statement
    printf("DEBUG: About to execute INSERT statement\n");
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT execute", err.message);
        printf("DEBUG: INSERT execute failed: %s\n", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }
    printf("DEBUG: INSERT statement executed successfully\n");

    // Commit transaction
    printf("DEBUG: About to commit transaction\n");
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("INSERT commit", err.message);
        printf("DEBUG: COMMIT failed: %s\n", err.message);
        for (int i = 0; i < 5; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }
    printf("DEBUG: Transaction committed successfully\n");

    // Cleanup
    for (int i = 0; i < 5; i++) {
        dpiVar_release(vars[i]);
    }
    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("INSERT", "Success");
    return 1;
}

int oracle_update_rejected_logon(double id,
                                const char *session_id,
                                const char *user_name,
                                const char *exp_res_code,
                                const char *origin_host,
                                const char *car_server_ip) {
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("UPDATE", "Pool not initialized");
        return 0;
    }

    if (!session_id || !user_name || !exp_res_code || !origin_host || !car_server_ip) {
        set_last_error_with_context("UPDATE", "NULL parameter provided");
        return 0;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return 0; // Error already set
    }

    dpiStmt *stmt = NULL;
    // Updated SQL for new table structure - no created_at2 column
    const char *sql = "UPDATE rejected_logons SET "
                     "session_id = :1, user_name = :2, exp_res_code = :3, "
                     "origin_host = :4, car_server_ip = :5 "
                     "WHERE id = :6";

    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Prepare statement
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create variables for binding
    dpiVar *vars[6];  // Updated: only 6 parameters now
    dpiData *data[6];

    // Create string variables for first 5 parameters
    for (int i = 0; i < 5; i++) {
        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES, 1, 4000, 1, 0, NULL, &vars[i], &data[i]) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("CREATE var", err.message);
            // Release already created vars
            for (int j = 0; j < i; j++) {
                dpiVar_release(vars[j]);
            }
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Create double variable for ID (6th parameter)
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_NUMBER, DPI_NATIVE_TYPE_DOUBLE, 1, 0, 1, 0, NULL, &vars[5], &data[5]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("CREATE var", err.message);
        // Release already created vars
        for (int j = 0; j < 5; j++) {
            dpiVar_release(vars[j]);
        }
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind parameters
    // :1 - session_id
    data[0]->isNull = 0;
    strncpy(data[0]->value.asBytes.ptr, session_id, 3999);
    data[0]->value.asBytes.ptr[3999] = '\0';
    data[0]->value.asBytes.length = strlen(data[0]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 1, vars[0]);

    // :2 - user_name
    data[1]->isNull = 0;
    strncpy(data[1]->value.asBytes.ptr, user_name, 3999);
    data[1]->value.asBytes.ptr[3999] = '\0';
    data[1]->value.asBytes.length = strlen(data[1]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 2, vars[1]);

    // :3 - exp_res_code
    data[2]->isNull = 0;
    strncpy(data[2]->value.asBytes.ptr, exp_res_code, 3999);
    data[2]->value.asBytes.ptr[3999] = '\0';
    data[2]->value.asBytes.length = strlen(data[2]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 3, vars[2]);

    // :4 - origin_host
    data[3]->isNull = 0;
    strncpy(data[3]->value.asBytes.ptr, origin_host, 3999);
    data[3]->value.asBytes.ptr[3999] = '\0';
    data[3]->value.asBytes.length = strlen(data[3]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 4, vars[3]);

    // :5 - car_server_ip
    data[4]->isNull = 0;
    strncpy(data[4]->value.asBytes.ptr, car_server_ip, 3999);
    data[4]->value.asBytes.ptr[3999] = '\0';
    data[4]->value.asBytes.length = strlen(data[4]->value.asBytes.ptr);
    dpiStmt_bindByPos(stmt, 5, vars[4]);

    // :6 - id
    data[5]->isNull = 0;
    data[5]->value.asDouble = id;
    dpiStmt_bindByPos(stmt, 6, vars[5]);

    // Execute statement
    printf("[UPDATE] Executing SQL: %s\n", sql);
    printf("[UPDATE] Parameters: id=%.0f, session_id=%s, user_name=%s, exp_res_code=%s, origin_host=%s, car_server_ip=%s\n",
           id, session_id, user_name, exp_res_code, origin_host, car_server_ip);

    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE execute", err.message);
        for (int i = 0; i < 6; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Check how many rows were affected
    uint64_t rowCount = 0;
    if (dpiStmt_getRowCount(stmt, &rowCount) == DPI_SUCCESS) {
        printf("[UPDATE] Rows affected: %lu\n", (unsigned long)rowCount);
        if (rowCount == 0) {
            printf("[UPDATE] WARNING: No rows were updated - ID %.0f may not exist\n", id);
        }
    } else {
        printf("[UPDATE] Could not get row count\n");
    }

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE commit", err.message);
        for (int i = 0; i < 6; i++) dpiVar_release(vars[i]);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Cleanup
    for (int i = 0; i < 6; i++) {
        dpiVar_release(vars[i]);
    }
    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("UPDATE", "Success");
    return 1;
}

/* Get last error message */
const char* oracle_get_last_error(void) {
    return g_pool_singleton.last_error;
}

/* Flexible update - only updates non-NULL fields */
int oracle_update_rejected_logon_fields(double id,
                                        const char *session_id,      // NULL = don't update
                                        const char *user_name,       // NULL = don't update
                                        const char *exp_res_code,    // NULL = don't update
                                        const char *origin_host,     // NULL = don't update
                                        const char *car_server_ip)   // NULL = don't update
{
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("UPDATE_FIELDS", "Oracle pool not initialized");
        return 0;
    }

    pthread_mutex_lock(&g_pool_singleton.mutex);
    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn) || !conn) {
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    // Build dynamic SQL based on which fields are provided
    char sql[1024] = "UPDATE rejected_logons SET ";
    char *sql_ptr = sql + strlen(sql);
    int field_count = 0;

    if (session_id) {
        sql_ptr += sprintf(sql_ptr, "%ssession_id = :session_id", field_count > 0 ? ", " : "");
        field_count++;
    }
    if (user_name) {
        sql_ptr += sprintf(sql_ptr, "%suser_name = :user_name", field_count > 0 ? ", " : "");
        field_count++;
    }
    if (exp_res_code) {
        sql_ptr += sprintf(sql_ptr, "%sexp_res_code = :exp_res_code", field_count > 0 ? ", " : "");
        field_count++;
    }
    if (origin_host) {
        sql_ptr += sprintf(sql_ptr, "%sorigin_host = :origin_host", field_count > 0 ? ", " : "");
        field_count++;
    }
    if (car_server_ip) {
        sql_ptr += sprintf(sql_ptr, "%scar_server_ip = :car_server_ip", field_count > 0 ? ", " : "");
        field_count++;
    }

    sprintf(sql_ptr, " WHERE id = :id");

    if (field_count == 0) {
        set_last_error_with_context("UPDATE_FIELDS", "No fields to update");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    printf("DEBUG: Flexible update SQL: %s\n", sql);

    dpiStmt *stmt = NULL;
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("PREPARE update_fields", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind ID parameter (always present)
    if (dpiStmt_bindValueByName(stmt, "id", 2, DPI_NATIVE_TYPE_DOUBLE, &id) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("BIND id", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind optional parameters
    if (session_id) {
        dpiData data;
        data.isNull = 0;
        data.value.asBytes.ptr = (char*)session_id;
        data.value.asBytes.length = strlen(session_id);
        if (dpiStmt_bindValueByName(stmt, "session_id", 10, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("BIND session_id", err.message);
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    if (user_name) {
        dpiData data;
        data.isNull = 0;
        data.value.asBytes.ptr = (char*)user_name;
        data.value.asBytes.length = strlen(user_name);
        if (dpiStmt_bindValueByName(stmt, "user_name", 9, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("BIND user_name", err.message);
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    if (exp_res_code) {
        dpiData data;
        data.isNull = 0;
        data.value.asBytes.ptr = (char*)exp_res_code;
        data.value.asBytes.length = strlen(exp_res_code);
        if (dpiStmt_bindValueByName(stmt, "exp_res_code", 12, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("BIND exp_res_code", err.message);
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    if (origin_host) {
        dpiData data;
        data.isNull = 0;
        data.value.asBytes.ptr = (char*)origin_host;
        data.value.asBytes.length = strlen(origin_host);
        if (dpiStmt_bindValueByName(stmt, "origin_host", 11, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("BIND origin_host", err.message);
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    if (car_server_ip) {
        dpiData data;
        data.isNull = 0;
        data.value.asBytes.ptr = (char*)car_server_ip;
        data.value.asBytes.length = strlen(car_server_ip);
        if (dpiStmt_bindValueByName(stmt, "car_server_ip", 13, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("BIND car_server_ip", err.message);
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Execute the update
    uint32_t numQueryColumns = 0;
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, &numQueryColumns) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("EXECUTE update_fields", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Get row count
    uint64_t rowCount = 0;
    dpiStmt_getRowCount(stmt, &rowCount);
    printf("DEBUG: Flexible update affected %lu rows\n", (unsigned long)rowCount);

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("COMMIT update_fields", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("UPDATE_FIELDS", "Success");
    return 1;
}

/* Flexible update function - only updates specified fields */
int oracle_update_rejected_logon_flexible(double id,
                                          const char *session_id,
                                          const char *user_name,
                                          const char *exp_res_code,
                                          const char *origin_host,
                                          const char *car_server_ip) {
    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("UPDATE_FIELDS", "Pool not initialized");
        return 0;
    }

    // Build dynamic SQL based on provided fields
    char sql[2048] = "UPDATE rejected_logons SET ";
    char *params[7];
    int param_count = 0;
    int first_field = 1;

    // Check each field and add to SQL if provided
    if (session_id != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "session_id = ?");
        params[param_count++] = (char*)session_id;
        first_field = 0;
    }

    if (user_name != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "user_name = ?");
        params[param_count++] = (char*)user_name;
        first_field = 0;
    }

    if (exp_res_code != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "exp_res_code = ?");
        params[param_count++] = (char*)exp_res_code;
        first_field = 0;
    }

    if (origin_host != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "origin_host = ?");
        params[param_count++] = (char*)origin_host;
        first_field = 0;
    }

    if (car_server_ip != NULL) {
        if (!first_field) strcat(sql, ", ");
        strcat(sql, "car_server_ip = ?");
        params[param_count++] = (char*)car_server_ip;
        first_field = 0;    }

    if (param_count == 0) {
        set_last_error_with_context("UPDATE_FIELDS", "No fields to update");
        return 0;
    }

    strcat(sql, " WHERE id = ?");

    printf("DEBUG: Dynamic SQL: %s\n", sql);
    printf("DEBUG: Parameter count: %d\n", param_count);

    dpiConn *conn = NULL;
    pthread_mutex_lock(&g_pool_singleton.mutex);

    if (oracle_acquire_singleton(&conn) != 0) {
        set_last_error_with_context("UPDATE_FIELDS", "Failed to acquire connection");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        return 0;
    }

    dpiStmt *stmt = NULL;
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_FIELDS prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Create variables and bind parameters
    dpiVar *vars[param_count + 1];  // +1 for ID parameter
    dpiData *data[param_count + 1];

    // Create string variables for field parameters
    for (int i = 0; i < param_count; i++) {
        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES, 1, 4000, 1, 0, NULL, &vars[i], &data[i]) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("UPDATE_FIELDS create var", err.message);
            // Cleanup
            for (int j = 0; j < i; j++) {
                dpiVar_release(vars[j]);
            }
            dpiStmt_release(stmt);
            pthread_mutex_unlock(&g_pool_singleton.mutex);
            oracle_release_singleton(conn);
            return 0;
        }
    }

    // Create double variable for ID
    if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_NUMBER, DPI_NATIVE_TYPE_DOUBLE, 1, 0, 1, 0, NULL, &vars[param_count], &data[param_count]) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_FIELDS create ID var", err.message);
        // Cleanup
        for (int j = 0; j < param_count; j++) {
            dpiVar_release(vars[j]);
        }
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Bind field parameters
    for (int i = 0; i < param_count; i++) {
        data[i]->isNull = 0;
        if (strcmp(params[i], ORACLE_SET_NULL) == 0) {
            data[i]->isNull = 1;
        } else {
            strncpy(data[i]->value.asBytes.ptr, params[i], 3999);
            data[i]->value.asBytes.ptr[3999] = '\0';
            data[i]->value.asBytes.length = strlen(data[i]->value.asBytes.ptr);
        }
        dpiStmt_bindByPos(stmt, i + 1, vars[i]);
    }

    // Bind ID parameter
    data[param_count]->isNull = 0;
    data[param_count]->value.asDouble = id;
    dpiStmt_bindByPos(stmt, param_count + 1, vars[param_count]);

    // Execute statement
    uint32_t numQueryColumns = 0;
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, &numQueryColumns) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_FIELDS execute", err.message);

        // Cleanup
        for (int j = 0; j <= param_count; j++) {
            dpiVar_release(vars[j]);
        }
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Commit transaction
    if (dpiConn_commit(conn) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("UPDATE_FIELDS commit", err.message);

        // Cleanup
        for (int j = 0; j <= param_count; j++) {
            dpiVar_release(vars[j]);
        }
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Cleanup
    for (int j = 0; j <= param_count; j++) {
        dpiVar_release(vars[j]);
    }
    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    printf("DEBUG: Successfully updated record ID %.0f\n", id);
    set_last_error_with_context("UPDATE_FIELDS", "Success");
    return 1;
}

/* ===== QUERY RESULT API ===== */

query_result_t* oracle_query_get_result(const char *sql, int max_rows) {
    if (!sql) {
        set_last_error_with_context("QUERY_GET_RESULT", "SQL is NULL");
        return NULL;
    }

    if (!oracle_pool_is_initialized()) {
        set_last_error_with_context("QUERY_GET_RESULT", "Pool not initialized");
        return NULL;
    }

    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        return NULL; // Error already set
    }

    dpiStmt *stmt = NULL;
    query_result_t *result = NULL;

    pthread_mutex_lock(&g_pool_singleton.mutex);

    // Prepare statement
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("QUERY_GET_RESULT prepare", err.message);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return NULL;
    }

    // Execute statement
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("QUERY_GET_RESULT execute", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return NULL;
    }

    // Get column count
    uint32_t cols = 0;
    if (dpiStmt_getNumQueryColumns(stmt, &cols) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        set_last_error_with_context("QUERY_GET_RESULT getNumQueryColumns", err.message);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return NULL;
    }

    // Allocate result structure
    result = calloc(1, sizeof(query_result_t));
    if (!result) {
        set_last_error_with_context("QUERY_GET_RESULT", "Memory allocation failed");
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return NULL;
    }

    result->max_rows = max_rows;
    result->row_count = 0;
    result->rows = calloc(max_rows, sizeof(char*));
    if (!result->rows) {
        set_last_error_with_context("QUERY_GET_RESULT", "Memory allocation for rows failed");
        free(result);
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return NULL;
    }

    // Fetch rows
    int found = 0;
    while (result->row_count < max_rows) {
        uint32_t bufferRowIndex = 0;
        if (dpiStmt_fetch(stmt, &found, &bufferRowIndex) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            set_last_error_with_context("QUERY_GET_RESULT fetch", err.message);
            break;
        }
        if (!found) {
            break; // No more rows
        }

        // Build row string from all columns
        char row_buffer[4096] = {0};
        char *row_ptr = row_buffer;
        int remaining = sizeof(row_buffer) - 1;

        for (uint32_t c = 1; c <= cols && remaining > 0; c++) {
            dpiNativeTypeNum type;
            dpiData *data;
            if (dpiStmt_getQueryValue(stmt, c, &type, &data) != DPI_SUCCESS) {
                dpiErrorInfo err;
                dpiContext_getError(g_pool_singleton.pool.ctx, &err);
                set_last_error_with_context("QUERY_GET_RESULT getQueryValue", err.message);
                break;
            }

            if (c > 1 && remaining > 2) {
                // Add separator between columns
                strncpy(row_ptr, " | ", remaining);
                row_ptr += 3;
                remaining -= 3;
            }

            if (data->isNull) {
                int len = snprintf(row_ptr, remaining, "NULL");
                if (len > 0 && len < remaining) {
                    row_ptr += len;
                    remaining -= len;
                }
            } else if (type == DPI_NATIVE_TYPE_BYTES) {
                int len = snprintf(row_ptr, remaining, "%.*s",
                                 (int)data->value.asBytes.length,
                                 (const char*)data->value.asBytes.ptr);
                if (len > 0 && len < remaining) {
                    row_ptr += len;
                    remaining -= len;
                }
            } else if (type == DPI_NATIVE_TYPE_INT64) {
                int len = snprintf(row_ptr, remaining, "%lld",
                                 (long long)data->value.asInt64);
                if (len > 0 && len < remaining) {
                    row_ptr += len;
                    remaining -= len;
                }
            } else if (type == DPI_NATIVE_TYPE_DOUBLE) {
                int len = snprintf(row_ptr, remaining, "%.0f",
                                 data->value.asDouble);
                if (len > 0 && len < remaining) {
                    row_ptr += len;
                    remaining -= len;
                }
            } else {
                int len = snprintf(row_ptr, remaining, "<type:%d>", (int)type);
                if (len > 0 && len < remaining) {
                    row_ptr += len;
                    remaining -= len;
                }
            }
        }

        // Store the row
        result->rows[result->row_count] = strdup(row_buffer);
        if (!result->rows[result->row_count]) {
            set_last_error_with_context("QUERY_GET_RESULT", "Memory allocation for row failed");
            break;
        }
        result->row_count++;
    }

    dpiStmt_release(stmt);
    pthread_mutex_unlock(&g_pool_singleton.mutex);
    oracle_release_singleton(conn);

    set_last_error_with_context("QUERY_GET_RESULT", "Success");
    return result;
}

void oracle_free_result(query_result_t *result) {
    if (!result) {
        return;
    }

    if (result->rows) {
        for (int i = 0; i < result->row_count; i++) {
            free(result->rows[i]);
        }
        free(result->rows);
    }

    free(result);
}

/* Query rejected logon records (with optional WHERE clause) */
int oracle_query_rejected_logons(const char *where_clause,
                                 rejected_logon_t **results,
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
            "SELECT id, session_id, user_name, exp_res_code, origin_host, "
            "TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, "
            "car_server_ip FROM rejected_logons WHERE %s ORDER BY id DESC",
            where_clause);
    } else {
        snprintf(sql, sizeof(sql),
            "SELECT id, session_id, user_name, exp_res_code, origin_host, "
            "TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at, "
            "car_server_ip FROM rejected_logons ORDER BY id DESC");
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
        print_connection_error(conn, "dpiConn_prepareStmt (query rejected_logons)", default_log);
        set_last_error("Failed to prepare query statement");
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, NULL) != DPI_SUCCESS) {
        print_connection_error(conn, "dpiStmt_execute (query rejected_logons)", default_log);
        set_last_error("Failed to execute query statement");
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Count results first
    uint32_t num_query_columns = 0;
    if (dpiStmt_getNumQueryColumns(stmt, &num_query_columns) != DPI_SUCCESS) {
        print_connection_error(conn, "dpiStmt_getNumQueryColumns", default_log);
        set_last_error("Failed to get column count");
        dpiStmt_release(stmt);
        pthread_mutex_unlock(&g_pool_singleton.mutex);
        oracle_release_singleton(conn);
        return 0;
    }

    // Allocate temporary array to count rows
    rejected_logon_t *temp_results = malloc(max_results > 0 ? max_results * sizeof(rejected_logon_t) : 1000 * sizeof(rejected_logon_t));
    if (!temp_results) {
        set_last_error("Memory allocation failed for query results");
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
    uint32_t numRowsFetched = 0;

    while (dpiStmt_fetch(stmt, &found, &bufferRowIndex) == DPI_SUCCESS && found) {
        if (row_count >= max_alloc) {
            break; // Stop if we've reached the limit
        }

        rejected_logon_t *current = &temp_results[row_count];
        memset(current, 0, sizeof(rejected_logon_t));

        // Get column data
        dpiData *data = NULL;
        dpiNativeTypeNum nativeTypeNum = 0;

        // Column 1: id (NUMBER -> double)
        if (dpiStmt_getQueryValue(stmt, 1, &nativeTypeNum, &data) == DPI_SUCCESS && data) {
            if (nativeTypeNum == DPI_NATIVE_TYPE_DOUBLE) {
                current->id = data->value.asDouble;
            } else if (nativeTypeNum == DPI_NATIVE_TYPE_INT64) {
                current->id = (double)data->value.asInt64;
            } else {
                current->id = 0.0;
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

        // Column 4: exp_res_code (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 4, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->exp_res_code)) len = sizeof(current->exp_res_code) - 1;
            memcpy(current->exp_res_code, data->value.asBytes.ptr, len);
            current->exp_res_code[len] = '\0';
        }

        // Column 5: origin_host (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 5, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->origin_host)) len = sizeof(current->origin_host) - 1;
            memcpy(current->origin_host, data->value.asBytes.ptr, len);
            current->origin_host[len] = '\0';
        }

        // Column 6: created_at (formatted TIMESTAMP)
        if (dpiStmt_getQueryValue(stmt, 6, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->created_at)) len = sizeof(current->created_at) - 1;
            memcpy(current->created_at, data->value.asBytes.ptr, len);
            current->created_at[len] = '\0';
        }

        // Column 7: car_server_ip (VARCHAR2)
        if (dpiStmt_getQueryValue(stmt, 7, &nativeTypeNum, &data) == DPI_SUCCESS && data && data->value.asBytes.ptr) {
            uint32_t len = data->value.asBytes.length;
            if (len >= sizeof(current->car_server_ip)) len = sizeof(current->car_server_ip) - 1;
            memcpy(current->car_server_ip, data->value.asBytes.ptr, len);
            current->car_server_ip[len] = '\0';
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
    snprintf(debug_msg, sizeof(debug_msg), "Query completed successfully, returned %d rows", row_count);
    set_last_error(debug_msg);

    return 1; // Success
}

/* Free results from oracle_query_rejected_logons */
void oracle_free_rejected_logons(rejected_logon_t *results) {
    if (results) {
        free(results);
    }
}

/* ===== EGYSZERŰ PARAMÉTERES LEKÉRDEZÉS IMPLEMENTÁCIÓ ===== */

/* Ultra-simple Oracle query - just checks if Oracle works */
int oracle_simple_query(const char *sql, const char *param_name, const char *param_value, char ***results, int *row_count) {
    // Initialize outputs
    if (results) *results = NULL;
    if (row_count) *row_count = 0;

    if (!sql) {
        set_last_error("SQL is NULL");
        return 0;
    }

    if (!oracle_pool_is_initialized()) {
        set_last_error("Oracle pool not initialized");
        return 0;
    }

    printf("oracle_simple_query: Starting query: %s\n", sql);

    // No mutex here - let acquire_singleton handle locking
    dpiConn *conn = NULL;
    if (!oracle_acquire_singleton(&conn)) {
        printf("oracle_simple_query: Failed to acquire connection\n");
        return 0;
    }

    // From here, we must release connection on any exit
    dpiStmt *stmt = NULL;
    int success = 0;

    // Prepare statement
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        printf("oracle_simple_query: Prepare failed: %.*s\n", err.messageLength, err.message);
        set_last_error("Failed to prepare statement");
        goto cleanup;
    }

    // Bind parameter if provided (use variables, not direct data)
    dpiVar *param_var = NULL;
    dpiData *param_data = NULL;
    if (param_name && param_value) {
        printf("oracle_simple_query: Binding parameter %s = %s\n", param_name, param_value);

        if (dpiConn_newVar(conn, DPI_ORACLE_TYPE_VARCHAR, DPI_NATIVE_TYPE_BYTES,
                          1, strlen(param_value) + 1, 1, 0, NULL, &param_var, &param_data) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            printf("oracle_simple_query: newVar failed: %.*s\n", err.messageLength, err.message);
            set_last_error("Failed to create parameter variable");
            goto cleanup;
        }

        // Set parameter value
        param_data->isNull = 0;
        strcpy((char*)param_data->value.asBytes.ptr, param_value);
        param_data->value.asBytes.length = strlen(param_value);

        if (dpiStmt_bindByName(stmt, param_name, strlen(param_name), param_var) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            printf("oracle_simple_query: Bind failed: %.*s\n", err.messageLength, err.message);
            set_last_error("Failed to bind parameter");
            goto cleanup;
        }
    }

    // Execute statement
    uint32_t num_columns = 0;
    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, &num_columns) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        printf("oracle_simple_query: Execute failed: %.*s\n", err.messageLength, err.message);
        set_last_error("Failed to execute statement");
        goto cleanup;
    }

    printf("oracle_simple_query: Query executed successfully, %u columns\n", num_columns);

    // If this is not a query (no columns), we're done
    if (num_columns == 0) {
        success = 1;
        goto cleanup;
    }

    // Allocate result array (small, safe size)
    char **result_rows = calloc(10, sizeof(char*)); // Max 10 rows
    if (!result_rows) {
        set_last_error("Failed to allocate result array");
        goto cleanup;
    }

    int count = 0;
    int found = 0;
    uint32_t buf_row_index = 0;

    printf("oracle_simple_query: Starting fetch...\n");

    // Fetch rows (limit to 10 for safety)
    while (count < 10) {
        if (dpiStmt_fetch(stmt, &found, &buf_row_index) != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            printf("oracle_simple_query: Fetch failed: %.*s\n", err.messageLength, err.message);
            break;
        }

        if (!found) {
            printf("oracle_simple_query: No more rows\n");
            break;
        }

        // Get first column value only
        dpiData *cell_data = NULL;
        dpiNativeTypeNum native_type = 0;

        if (dpiStmt_getQueryValue(stmt, 1, &native_type, &cell_data) == DPI_SUCCESS && cell_data) {
            char buffer[256] = {0};

            if (cell_data->isNull) {
                strcpy(buffer, "NULL");
            } else if (native_type == DPI_NATIVE_TYPE_BYTES) {
                snprintf(buffer, sizeof(buffer), "%.*s",
                        (int)cell_data->value.asBytes.length,
                        (const char*)cell_data->value.asBytes.ptr);
            } else if (native_type == DPI_NATIVE_TYPE_DOUBLE) {
                snprintf(buffer, sizeof(buffer), "%.0f", cell_data->value.asDouble);
            } else if (native_type == DPI_NATIVE_TYPE_INT64) {
                snprintf(buffer, sizeof(buffer), "%ld", cell_data->value.asInt64);
            } else {
                snprintf(buffer, sizeof(buffer), "(type:%d)", (int)native_type);
            }

            result_rows[count] = malloc(strlen(buffer) + 1);
            if (result_rows[count]) {
                strcpy(result_rows[count], buffer);
                printf("oracle_simple_query: Row %d: %s\n", count, buffer);
                count++;
            }
        } else {
            printf("oracle_simple_query: Failed to get column value for row %d\n", count);
            break;
        }
    }

    printf("oracle_simple_query: Fetched %d rows total\n", count);

    if (results) *results = result_rows;
    if (row_count) *row_count = count;
    success = 1;

cleanup:
    if (param_var) {
        dpiVar_release(param_var);
    }
    if (stmt) {
        dpiStmt_release(stmt);
    }
    oracle_release_singleton(conn);

    printf("oracle_simple_query: Cleanup complete, success=%d\n", success);
    return success;
}

/* Cleanup function for simple query results */
void oracle_free_simple_query(char **results, int row_count) {
    if (results) {
        for (int i = 0; i < row_count; i++) {
            if (results[i]) {
                free(results[i]);
            }
        }
        free(results);
    }
}

/* ===== PARAMETERIZED QUERY SUPPORT ===== */

/* Helper functions for creating parameters */
oracle_param_t oracle_param_string(const char *name, const char *value) {
    oracle_param_t param;
    param.name = name;
    param.type = ORACLE_PARAM_STRING;
    param.value.str_val = value;
    return param;
}

oracle_param_t oracle_param_double(const char *name, double value) {
    oracle_param_t param;
    param.name = name;
    param.type = ORACLE_PARAM_DOUBLE;
    param.value.dbl_val = value;
    return param;
}

oracle_param_t oracle_param_int(const char *name, int value) {
    oracle_param_t param;
    param.name = name;
    param.type = ORACLE_PARAM_INT;
    param.value.int_val = value;
    return param;
}

/* Execute parameterized SELECT query with binding support */
int oracle_query_parameterized(const char *sql,
                               oracle_param_t *params,
                               int param_count,
                               oracle_query_result_t **result,
                               int max_rows) {
    if (!sql || !result) {
        set_last_error("Invalid parameters: sql or result is NULL");
        return 0;
    }

    if (!oracle_pool_is_initialized()) {
        set_last_error("Pool not initialized");
        return 0;
    }

    if (max_rows <= 0) {
        max_rows = 1000; // Default limit
    }

    *result = NULL;

    dpiConn *conn = NULL;

    if (!oracle_acquire_singleton(&conn)) {
        return 0; // Error already set by acquire
    }

    dpiStmt *stmt = NULL;
    if (dpiConn_prepareStmt(conn, 0, sql, strlen(sql), NULL, 0, &stmt) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        printf("DEBUG: Failed to prepare statement: %.*s\n", err.messageLength, err.message);
        set_last_error_with_context("PARAM_QUERY", err.message);
        oracle_release_singleton(conn);
        return 0;
    }

    // Use consistent approach for all parameter binding - only use dpiStmt_bindValueByName
    printf("DEBUG: Binding %d parameters...\n", param_count);
    for (int i = 0; i < param_count; i++) {
        oracle_param_t *p = &params[i];
        printf("DEBUG: Binding parameter %d: name='%s', type=%d\n", i, p->name ? p->name : "NULL", p->type);
        if (!p->name) {
            char err[256];
            snprintf(err, sizeof(err), "Parameter %d has NULL name", i);
            set_last_error_with_context("PARAM_QUERY", err);
            dpiStmt_release(stmt);
            oracle_release_singleton(conn);
            return 0;
        }

        uint32_t name_len = strlen(p->name);
        dpiData data;
        memset(&data, 0, sizeof(data));

        switch (p->type) {
            case ORACLE_PARAM_STRING: {
                printf("DEBUG: Binding string parameter '%s' = '%s'\n", p->name, p->value.str_val ? p->value.str_val : "NULL");
                if (p->value.str_val) {
                    data.isNull = 0;
                    data.value.asBytes.ptr = (char*)p->value.str_val;
                    data.value.asBytes.length = strlen(p->value.str_val);
                    if (dpiStmt_bindValueByName(stmt, p->name, name_len, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
                        dpiErrorInfo err;
                        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
                        printf("DEBUG: Failed to bind string parameter '%s': %.*s\n", p->name, err.messageLength, err.message);
                        char err_msg[512];
                        snprintf(err_msg, sizeof(err_msg), "Failed to bind string parameter '%s': %.*s", p->name, err.messageLength, err.message);
                        set_last_error_with_context("PARAM_QUERY", err_msg);
                        dpiStmt_release(stmt);
                        oracle_release_singleton(conn);
                        return 0;
                    }
                    printf("DEBUG: Successfully bound string parameter '%s'\n", p->name);
                } else {
                    data.isNull = 1;
                    if (dpiStmt_bindValueByName(stmt, p->name, name_len, DPI_NATIVE_TYPE_BYTES, &data) != DPI_SUCCESS) {
                        dpiErrorInfo err;
                        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
                        printf("DEBUG: Failed to bind NULL string parameter '%s': %.*s\n", p->name, err.messageLength, err.message);
                        char err_msg[512];
                        snprintf(err_msg, sizeof(err_msg), "Failed to bind NULL string parameter '%s': %.*s", p->name, err.messageLength, err.message);
                        set_last_error_with_context("PARAM_QUERY", err_msg);
                        dpiStmt_release(stmt);
                        oracle_release_singleton(conn);
                        return 0;
                    }
                    printf("DEBUG: Successfully bound NULL string parameter '%s'\n", p->name);
                }
                break;
            }
            case ORACLE_PARAM_DOUBLE: {
                data.isNull = 0;
                data.value.asDouble = p->value.dbl_val;
                if (dpiStmt_bindValueByName(stmt, p->name, name_len, DPI_NATIVE_TYPE_DOUBLE, &data) != DPI_SUCCESS) {
                    dpiErrorInfo err;
                    dpiContext_getError(g_pool_singleton.pool.ctx, &err);
                    printf("DEBUG: Failed to bind double parameter '%s': %.*s\n", p->name, err.messageLength, err.message);
                    char err_msg[512];
                    snprintf(err_msg, sizeof(err_msg), "Failed to bind double parameter '%s': %.*s", p->name, err.messageLength, err.message);
                    set_last_error_with_context("PARAM_QUERY", err_msg);
                    dpiStmt_release(stmt);
                    oracle_release_singleton(conn);
                    return 0;
                }
                printf("DEBUG: Successfully bound double parameter '%s' = %f\n", p->name, p->value.dbl_val);
                break;
            }
            case ORACLE_PARAM_INT: {
                data.isNull = 0;
                data.value.asDouble = (double)p->value.int_val;
                if (dpiStmt_bindValueByName(stmt, p->name, name_len, DPI_NATIVE_TYPE_DOUBLE, &data) != DPI_SUCCESS) {
                    dpiErrorInfo err;
                    dpiContext_getError(g_pool_singleton.pool.ctx, &err);
                    printf("DEBUG: Failed to bind int parameter '%s': %.*s\n", p->name, err.messageLength, err.message);
                    char err_msg[512];
                    snprintf(err_msg, sizeof(err_msg), "Failed to bind int parameter '%s': %.*s", p->name, err.messageLength, err.message);
                    set_last_error_with_context("PARAM_QUERY", err_msg);
                    dpiStmt_release(stmt);
                    oracle_release_singleton(conn);
                    return 0;
                }
                printf("DEBUG: Successfully bound int parameter '%s' = %d\n", p->name, p->value.int_val);
                break;
            }
            default: {
                char err[256];
                snprintf(err, sizeof(err), "Unknown parameter type %d for parameter '%s'", p->type, p->name);
                set_last_error_with_context("PARAM_QUERY", err);
                dpiStmt_release(stmt);
                oracle_release_singleton(conn);
                return 0;
            }
        }
    }

    // Execute the query
    uint32_t num_columns = 0;
    printf("DEBUG: About to execute statement...\n");

    if (dpiStmt_execute(stmt, DPI_MODE_EXEC_DEFAULT, &num_columns) != DPI_SUCCESS) {
        dpiErrorInfo err;
        dpiContext_getError(g_pool_singleton.pool.ctx, &err);
        printf("DEBUG: Statement execution FAILED: %.*s\n", err.messageLength, err.message);
        set_last_error_with_context("PARAM_QUERY", err.message);
        dpiStmt_release(stmt);
        oracle_release_singleton(conn);
        return 0;
    }

    printf("DEBUG: Statement executed successfully, num_columns = %u\n", num_columns);

    // Allocate result structure
    oracle_query_result_t *query_result = calloc(1, sizeof(oracle_query_result_t));
    if (!query_result) {
        set_last_error_with_context("PARAM_QUERY", "Failed to allocate result structure");
        dpiStmt_release(stmt);
        oracle_release_singleton(conn);
        return 0;
    }

    query_result->column_count = num_columns;
    query_result->max_rows = max_rows;

    // Get column names
    if (num_columns > 0) {
        query_result->column_names = calloc(num_columns, sizeof(char*));
        if (!query_result->column_names) {
            set_last_error_with_context("PARAM_QUERY", "Failed to allocate column names");
            free(query_result);
            dpiStmt_release(stmt);
            oracle_release_singleton(conn);
            return 0;
        }

        for (uint32_t i = 0; i < num_columns; i++) {
            dpiQueryInfo queryInfo;
            if (dpiStmt_getQueryInfo(stmt, i + 1, &queryInfo) == DPI_SUCCESS && queryInfo.name) {
                query_result->column_names[i] = malloc(queryInfo.nameLength + 1);
                if (query_result->column_names[i]) {
                    memcpy(query_result->column_names[i], queryInfo.name, queryInfo.nameLength);
                    query_result->column_names[i][queryInfo.nameLength] = '\0';
                    printf("DEBUG: Column %u name: '%s'\n", i + 1, query_result->column_names[i]);
                }
            }
        }
    }

    // Allocate rows array
    query_result->rows = calloc(max_rows, sizeof(char**));
    if (!query_result->rows) {
        set_last_error_with_context("PARAM_QUERY", "Failed to allocate rows array");
        oracle_free_query_result(query_result);
        dpiStmt_release(stmt);
        oracle_release_singleton(conn);
        return 0;
    }

    // Fetch rows - use a simpler approach
    int row_count = 0;
    int found = 0;
    int fetch_error = 0;
    printf("DEBUG: Starting to fetch rows...\n");

    // Fetch rows one by one
    while (row_count < max_rows && !fetch_error) {
        uint32_t buffer_row_index = 0;
        int fetch_result = dpiStmt_fetch(stmt, &found, &buffer_row_index);

        if (fetch_result != DPI_SUCCESS) {
            dpiErrorInfo err;
            dpiContext_getError(g_pool_singleton.pool.ctx, &err);
            printf("DEBUG: Fetch failed: %.*s\n", err.messageLength, err.message);
            fetch_error = 1;
            break;
        }

        if (!found) {
            printf("DEBUG: No more rows found, stopping fetch loop\n");
            break;
        }

        printf("DEBUG: Processing row %d\n", row_count);

        // Allocate row
        query_result->rows[row_count] = calloc(num_columns, sizeof(char*));
        if (!query_result->rows[row_count]) {
            printf("DEBUG: Failed to allocate memory for row %d\n", row_count);
            fetch_error = 1;
            break;
        }

        // Get column values for current row
        int row_complete = 1;
        for (uint32_t col = 0; col < num_columns && row_complete; col++) {
            uint32_t nativeTypeNum;
            dpiData *data;

            if (dpiStmt_getQueryValue(stmt, col + 1, &nativeTypeNum, &data) == DPI_SUCCESS && data) {
                if (data->isNull) {
                    query_result->rows[row_count][col] = strdup("NULL");
                    printf("DEBUG: Row %d, Column %u is NULL\n", row_count, col + 1);
                } else {
                    char temp_buf[4096]; // Increased buffer size
                    memset(temp_buf, 0, sizeof(temp_buf));

                    switch (nativeTypeNum) {
                        case DPI_NATIVE_TYPE_BYTES: {
                            uint32_t len = data->value.asBytes.length;
                            if (len >= sizeof(temp_buf)) len = sizeof(temp_buf) - 1;
                            if (len > 0 && data->value.asBytes.ptr) {
                                memcpy(temp_buf, data->value.asBytes.ptr, len);
                            }
                            temp_buf[len] = '\0';
                            query_result->rows[row_count][col] = strdup(temp_buf);
                            printf("DEBUG: Row %d, Column %u (BYTES): '%s'\n", row_count, col + 1, temp_buf);
                            break;
                        }
                        case DPI_NATIVE_TYPE_DOUBLE: {
                            snprintf(temp_buf, sizeof(temp_buf), "%.15g", data->value.asDouble);
                            query_result->rows[row_count][col] = strdup(temp_buf);
                            printf("DEBUG: Row %d, Column %u (DOUBLE): '%s'\n", row_count, col + 1, temp_buf);
                            break;
                        }
                        case DPI_NATIVE_TYPE_TIMESTAMP: {
                            dpiTimestamp *ts = &data->value.asTimestamp;
                            snprintf(temp_buf, sizeof(temp_buf), "%04d-%02d-%02d %02d:%02d:%02d",
                                   ts->year, ts->month, ts->day, ts->hour, ts->minute, ts->second);
                            query_result->rows[row_count][col] = strdup(temp_buf);
                            printf("DEBUG: Row %d, Column %u (TIMESTAMP): '%s'\n", row_count, col + 1, temp_buf);
                            break;
                        }
                        default:
                            snprintf(temp_buf, sizeof(temp_buf), "TYPE_%d", nativeTypeNum);
                            query_result->rows[row_count][col] = strdup(temp_buf);
                            printf("DEBUG: Row %d, Column %u (UNKNOWN TYPE %u)\n", row_count, col + 1, nativeTypeNum);
                            break;
                    }
                }
            } else {
                query_result->rows[row_count][col] = strdup("ERROR");
                printf("DEBUG: Row %d, Column %u - failed to get value\n", row_count, col + 1);
                // Don't break the entire fetch, just mark this column as error
            }
        }

        if (row_complete) {
            row_count++;
            printf("DEBUG: Row %d completed successfully\n", row_count);
        } else {
            printf("DEBUG: Row %d incomplete, stopping fetch\n", row_count);
            break;
        }
    }

    if (fetch_error) {
        printf("DEBUG: Fetch encountered errors, but continuing with %d rows\n", row_count);
    }

    printf("DEBUG: Finished fetching, total rows = %d\n", row_count);

    query_result->row_count = row_count;

    dpiStmt_release(stmt);
    oracle_release_singleton(conn);

    *result = query_result;

    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), "Parameterized query completed successfully, returned %d rows", row_count);
    set_last_error(debug_msg);

    return 1; // Success
}

/* Free parameterized query result */
void oracle_free_query_result(oracle_query_result_t *result) {
    if (!result) return;

    // Free column names
    if (result->column_names) {
        for (int i = 0; i < result->column_count; i++) {
            if (result->column_names[i]) {
                free(result->column_names[i]);
            }
        }
        free(result->column_names);
    }

    // Free rows
    if (result->rows) {
        for (int i = 0; i < result->row_count; i++) {
            if (result->rows[i]) {
                for (int j = 0; j < result->column_count; j++) {
                    if (result->rows[i][j]) {
                        free(result->rows[i][j]);
                    }
                }
                free(result->rows[i]);
            }
        }
        free(result->rows);
    }

    free(result);
}


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
    if (!oracle_acquire_singleton(&conn)) {
        set_last_error_with_context("UPDATE_SESSION_LOG_FIELDS", "Failed to acquire connection");
        return 0;
    }

    pthread_mutex_lock(&g_pool_singleton.mutex);

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
    dpiData id_data;
    id_data.isNull = 0;
    id_data.value.asDouble = id;
    if (dpiStmt_bindValueByName(stmt, "id", 2, DPI_NATIVE_TYPE_DOUBLE, &id_data) != DPI_SUCCESS) {
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
        dpiData session_data;
        if (strcmp(session_id, ORACLE_SET_NULL) == 0) {
            session_data.isNull = 1;
        } else {
            session_data.isNull = 0;
            session_data.value.asBytes.ptr = (char*)session_id;
            session_data.value.asBytes.length = strlen(session_id);
        }
        dpiStmt_bindValueByName(stmt, "session_id", 10, DPI_NATIVE_TYPE_BYTES, &session_data);
    }

    if (user_name != NULL) {
        dpiData user_data;
        if (strcmp(user_name, ORACLE_SET_NULL) == 0) {
            user_data.isNull = 1;
        } else {
            user_data.isNull = 0;
            user_data.value.asBytes.ptr = (char*)user_name;
            user_data.value.asBytes.length = strlen(user_name);
        }
        dpiStmt_bindValueByName(stmt, "user_name", 9, DPI_NATIVE_TYPE_BYTES, &user_data);
    }

    if (origin_state_id != -1) {
        dpiData origin_data;
        if (origin_state_id == -2) {
            origin_data.isNull = 1;
        } else {
            origin_data.isNull = 0;
            origin_data.value.asDouble = origin_state_id;
        }
        dpiStmt_bindValueByName(stmt, "origin_state_id", 15, DPI_NATIVE_TYPE_DOUBLE, &origin_data);
    }

    if (auth_request_type != NULL) {
        dpiData auth_data;
        if (strcmp(auth_request_type, ORACLE_SET_NULL) == 0) {
            auth_data.isNull = 1;
        } else {
            auth_data.isNull = 0;
            auth_data.value.asBytes.ptr = (char*)auth_request_type;
            auth_data.value.asBytes.length = strlen(auth_request_type);
        }
        dpiStmt_bindValueByName(stmt, "auth_request_type", 17, DPI_NATIVE_TYPE_BYTES, &auth_data);
    }

    if (calling_station_id != NULL) {
        dpiData calling_data;
        if (strcmp(calling_station_id, ORACLE_SET_NULL) == 0) {
            calling_data.isNull = 1;
        } else {
            calling_data.isNull = 0;
            calling_data.value.asBytes.ptr = (char*)calling_station_id;
            calling_data.value.asBytes.length = strlen(calling_station_id);
        }
        dpiStmt_bindValueByName(stmt, "calling_station_id", 18, DPI_NATIVE_TYPE_BYTES, &calling_data);
    }

    if (ip_address != NULL) {
        dpiData ip_data;
        if (strcmp(ip_address, ORACLE_SET_NULL) == 0) {
            ip_data.isNull = 1;
        } else {
            ip_data.isNull = 0;
            ip_data.value.asBytes.ptr = (char*)ip_address;
            ip_data.value.asBytes.length = strlen(ip_address);
        }
        dpiStmt_bindValueByName(stmt, "ip_address", 10, DPI_NATIVE_TYPE_BYTES, &ip_data);
    }

    if (msisdn != NULL) {
        dpiData msisdn_data;
        if (strcmp(msisdn, ORACLE_SET_NULL) == 0) {
            msisdn_data.isNull = 1;
        } else {
            msisdn_data.isNull = 0;
            msisdn_data.value.asBytes.ptr = (char*)msisdn;
            msisdn_data.value.asBytes.length = strlen(msisdn);
        }
        dpiStmt_bindValueByName(stmt, "msisdn", 6, DPI_NATIVE_TYPE_BYTES, &msisdn_data);
    }

    if (active != '\0') {
        dpiData active_data;
        char active_str[2] = {active, '\0'};
        if (active == 'X') { // Special value to indicate NULL
            active_data.isNull = 1;
        } else {
            active_data.isNull = 0;
            active_data.value.asBytes.ptr = active_str;
            active_data.value.asBytes.length = 1;
        }
        dpiStmt_bindValueByName(stmt, "active", 6, DPI_NATIVE_TYPE_BYTES, &active_data);
    }

    if (service_selection != NULL) {
        dpiData service_data;
        if (strcmp(service_selection, ORACLE_SET_NULL) == 0) {
            service_data.isNull = 1;
        } else {
            service_data.isNull = 0;
            service_data.value.asBytes.ptr = (char*)service_selection;
            service_data.value.asBytes.length = strlen(service_selection);
        }
        dpiStmt_bindValueByName(stmt, "service_selection", 17, DPI_NATIVE_TYPE_BYTES, &service_data);
    }

    if (start_timestamp != NULL) {
        dpiData start_data;
        if (strcmp(start_timestamp, ORACLE_SET_NULL) == 0) {
            start_data.isNull = 1;
        } else {
            start_data.isNull = 0;
            start_data.value.asBytes.ptr = (char*)start_timestamp;
            start_data.value.asBytes.length = strlen(start_timestamp);
        }
        dpiStmt_bindValueByName(stmt, "start_timestamp", 15, DPI_NATIVE_TYPE_BYTES, &start_data);
    }

    if (stop_timestamp != NULL) {
        dpiData stop_data;
        if (strcmp(stop_timestamp, ORACLE_SET_NULL) == 0) {
            stop_data.isNull = 1;
        } else {
            stop_data.isNull = 0;
            stop_data.value.asBytes.ptr = (char*)stop_timestamp;
            stop_data.value.asBytes.length = strlen(stop_timestamp);
        }
        dpiStmt_bindValueByName(stmt, "stop_timestamp", 14, DPI_NATIVE_TYPE_BYTES, &stop_data);
    }

    if (termination_cause != NULL) {
        dpiData term_data;
        if (strcmp(termination_cause, ORACLE_SET_NULL) == 0) {
            term_data.isNull = 1;
        } else {
            term_data.isNull = 0;
            term_data.value.asBytes.ptr = (char*)termination_cause;
            term_data.value.asBytes.length = strlen(termination_cause);
        }
        dpiStmt_bindValueByName(stmt, "termination_cause", 17, DPI_NATIVE_TYPE_BYTES, &term_data);
    }

    if (car_server_ip != NULL) {
        dpiData car_data;
        if (strcmp(car_server_ip, ORACLE_SET_NULL) == 0) {
            car_data.isNull = 1;
        } else {
            car_data.isNull = 0;
            car_data.value.asBytes.ptr = (char*)car_server_ip;
            car_data.value.asBytes.length = strlen(car_server_ip);
        }
        dpiStmt_bindValueByName(stmt, "car_server_ip", 13, DPI_NATIVE_TYPE_BYTES, &car_data);
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
