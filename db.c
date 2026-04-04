#include "db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

static sqlite3* db = NULL;

int db_init(const char* filename) {
    int rc = sqlite3_open(filename, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Note: Impact of DB locking on performance
    // SQLite uses file locking. In a high-concurrency environment, writer threads
    // may block each other. Since we are using an I/O multiplexing model (select),
    // everything runs in a single process/thread, meaning transactions happen sequentially.
    // This avoids thread-level DB contention but can block our I/O event loop if a write
    // to the disk takes too long (e.g., IO bottleneck). In a heavy production system,
    // disk writes would be offloaded to a background thread to prevent blocking `select()`.
    
    // Use default journal mode (DELETE) because WAL causes disk I/O errors on WSL mounted drives
    sqlite3_exec(db, "PRAGMA journal_mode=DELETE;", 0, 0, 0);

    const char* sql_create = 
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, "
        "password_hash TEXT);"
        
        "CREATE TABLE IF NOT EXISTS devices ("
        "id TEXT PRIMARY KEY, "
        "name TEXT, "
        "type TEXT, "
        "status TEXT);"
        
        "CREATE TABLE IF NOT EXISTS logs ("
        "id INTEGER PRIMARY KEY, "
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "device_id TEXT, "
        "action TEXT);";
        
    char* err_msg = NULL;
    rc = sqlite3_exec(db, sql_create, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }
    return 0;
}

int db_update_device_status(const char* device_id, const char* status) {
    if (!db) return -1;
    
    // Upsert logic (requires SQLite 3.24.0+)
    const char* sql = "INSERT INTO devices (id, name, type, status) VALUES (?, 'unknown', 'unknown', ?) "
                      "ON CONFLICT(id) DO UPDATE SET status=excluded.status;";
                      
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, status, -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int db_log_action(const char* device_id, const char* action) {
    if (!db) return -1;
    
    const char* sql = "INSERT INTO logs (device_id, action) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_text(stmt, 1, device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, action, -1, SQLITE_TRANSIENT);
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

int db_verify_user(const char* username, const char* password_hash) {
    if (!db) return 0;
    
    int result = 0;
    const char* sql = "SELECT id FROM users WHERE username = ? AND password_hash = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = 1;
        }
        sqlite3_finalize(stmt);
    }
    return result;
}

int db_add_user(const char* username, const char* password_hash) {
    if (!db) return -1;
    
    const char* sql = "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

void db_close() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}
