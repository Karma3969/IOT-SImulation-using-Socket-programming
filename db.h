#ifndef DB_H
#define DB_H

// Initialize the SQLite database and create tables if they do not exist.
int db_init(const char* filename);

// Update or insert a device's current status into the devices table.
int db_update_device_status(const char* device_id, const char* status);

// Log an action (e.g. command sent, status update received) with a timestamp.
int db_log_action(const char* device_id, const char* action);

// Verify user credentials
int db_verify_user(const char* username, const char* password_hash);

// Add user
int db_add_user(const char* username, const char* password_hash);

// Close the SQLite database connection.
void db_close();

#endif // DB_H
