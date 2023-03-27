/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "wtmpdb.h"

static sqlite3 *
open_database_ro (const char *path, char **error)
{
  sqlite3 *db;

  if (sqlite3_open_v2 (path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Cannot open database (%s): %s",
		      path, sqlite3_errmsg (db)) < 0)
	  *error = strdup ("Out of memory");
      sqlite3_close (db);
      return NULL;
    }

  return db;
}

static sqlite3 *
open_database_rw (const char *path, char **error)
{
  sqlite3 *db;

  if (sqlite3_open (path, &db) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "Cannot create/open database (%s): %s",
		      path, sqlite3_errmsg (db)) < 0)
	  *error = strdup ("Out of memory");

      sqlite3_close (db);
      return NULL;
    }

  return db;
}

/* Add a new entry. Returns rowid (>=0) on success, -1 on failure. */
static int64_t
add_entry (sqlite3 *db, int type, const char *user, pid_t pid,
	   usec_t login, const char *tty, const char *rhost,
	   const char *service, char **error)
{
  char *err_msg = NULL;
  sqlite3_stmt *res;
  char *sql_table = "CREATE TABLE IF NOT EXISTS wtmp(Type INTEGER, User TEXT NOT NULL, PID INTEGER, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT;";
  char *sql_insert = "INSERT INTO wtmp (Type,User,PID,Login,TTY,RemoteHost,Service) VALUES(?,?,?,?,?,?,?);";

  if (sqlite3_exec (db, sql_table, 0, 0, &err_msg) != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "SQL error: %s", err_msg) < 0)
	  *error = strdup ("Out of memory");
      sqlite3_free (err_msg);

      return -1;
    }

  if (sqlite3_prepare_v2 (db, sql_insert, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_int (res, 1, type) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for type: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 2, user, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for user: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      sqlite3_finalize (res);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 3, pid) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for PID: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 4, login) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 5, tty, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for tty: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 6, rhost, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for rhost: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 7, service, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for service: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step != SQLITE_DONE)
    {
      if (error)
        if (asprintf (error, "Adding an entry did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  sqlite3_finalize(res);

  return sqlite3_last_insert_rowid(db);
}

/*
  Add new wtmp entry to db.
  login is usec.
  Returns 0 on success, -1 on failure.
 */
int64_t
wtmpdb_login (const char *db_path, int type, const char *user, pid_t pid,
	      usec_t login, const char *tty, const char *rhost,
	      const char *service, char **error)
{
  sqlite3 *db;
  int64_t retval;

  if ((db = open_database_rw (db_path, error)) == NULL)
    return -1;

  retval = add_entry (db, type, user, pid, login, tty, rhost, service, error);

  sqlite3_close (db);

  return retval;
}

/* Updates logout field
   Returns 0 on success, -1 on failure. */
static int
update_logout (sqlite3 *db, int64_t id, usec_t logout, char **error)
{
  sqlite3_stmt *res;
  char *sql = "UPDATE wtmp SET Logout = ? WHERE rowid = ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, logout) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create update query (logout): %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 2, id) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create update query (rowid): %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step != SQLITE_DONE)
    {
      if (error)
        if (asprintf (error, "Updating logout time did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int changes;
  if ((changes = sqlite3_changes (db)) != 1)
    {
      if (error)
        if (asprintf (error, "Updated wrong number of rows, expected 1, got %d",
                      changes) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  sqlite3_finalize (res);

  return 0;
}


/*
  Add logout timestamp to existingentry.
  logout is usec.
  id is the return value of wtmpdb_login/logwtmpdb.
  Returns 0 on success, -1 on failure.
 */
int
wtmpdb_logout (const char *db_path, int64_t id, usec_t logout, char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_rw (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    return -1;

  retval = update_logout (db, id, logout, error);

  sqlite3_close (db);

  return retval;
}
