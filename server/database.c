#include <sqlite3.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static sqlite3 *db_handle = NULL;

int db_init(){ 
    char *err_msg = 0;
    int rc;
    rc = sqlite3_open("./users.db", &db_handle);

    if(rc != SQLITE_OK){
        MessageBox(NULL, sqlite3_errmsg(db_handle), "DB Open Error, opening", MB_OK | MB_ICONERROR);;
        return rc;
    }

    const char *query = "CREATE TABLE IF NOT EXISTS users (""id INTEGER PRIMARY KEY AUTOINCREMENT, ""username TEXT NOT NULL UNIQUE, ""password_hash TEXT NOT NULL"");";

    rc = sqlite3_exec(db_handle, query, 0, 0, &err_msg);

    if(rc != SQLITE_OK){
        MessageBox(NULL, sqlite3_errmsg(db_handle), "DB Open Error, after query", MB_OK | MB_ICONERROR);
        sqlite3_free(err_msg);
        return rc;
    }
    return 0;

}

int db_register_user(const char *username, const char *password_hash)
{
    int rc;
    sqlite3_stmt *stmt = NULL;

    const char *query =
        "INSERT INTO users (username, password_hash) VALUES (?, ?);";

    rc = sqlite3_prepare_v2(db_handle, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_step(stmt);

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return rc;
    }

    return 0;
}


int db_login_user(const char *username, const char *password_hash){
    int rc;
    sqlite3_stmt *stmt = NULL;

    const char *query = "SELECT 1 FROM users WHERE username = ? AND password_hash = ?;";

    rc = sqlite3_prepare_v2(db_handle, query, -1, &stmt, NULL);
    if(rc != SQLITE_OK){
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    if(rc != SQLITE_OK){
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT);
    if(rc != SQLITE_OK){
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_step(stmt);

    sqlite3_finalize(stmt);

    if(rc == SQLITE_ROW){ //success
        return 0;
    } 
    else if(rc == SQLITE_DONE){ //not found
        return 1;
    } 
    else { //error
     
        return rc;
    }
}

int db_close(void){ //no need to check for unfinalized query beacuse each request gets finalzied
    if(db_handle != NULL){
        return sqlite3_close(db_handle);
    }
    return -1;
}

