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
#include <libgen.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "wtmpdb.h"

/* Begin - local helper functions */

static void
mkdir_p(const char *pathname, mode_t mode)
{
  if (mkdir(pathname, mode) == 0 || errno == EEXIST || errno != ENOENT)
    return;

  char *buf = strdup(pathname);
  mkdir_p(dirname(buf), mode);
  free(buf);

  mkdir(pathname, mode);
}

static void strip_extension(char *in_str)
{
    static const int name_min_len = 1;
    static const int max_ext_len = 4;

    /* Check chars starting at end of string to find last '.' */
    for (ssize_t i = strlen(in_str); i > (name_min_len + max_ext_len); i--)
    {
        if (in_str[i] == '.')
        {
            in_str[i] = '\0';
            return;
        }
    }
}

/* End - local helper functions */


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

  char *buf = strdup(path);
  mkdir_p(dirname(buf), 0644);
  free(buf);

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

/* Add a new entry. Returns ID (>=0) on success, -1 on failure. */
static int64_t
add_entry (sqlite3 *db, int type, const char *user,
	   uint64_t usec_login, const char *tty, const char *rhost,
	   const char *service, char **error)
{
  char *err_msg = NULL;
  sqlite3_stmt *res;
  char *sql_table = "CREATE TABLE IF NOT EXISTS wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT;";
  char *sql_insert = "INSERT INTO wtmp (Type,User,Login,TTY,RemoteHost,Service) VALUES(?,?,?,?,?,?);";

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

  if (sqlite3_bind_int64 (res, 3, usec_login) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 4, tty, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for tty: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 5, rhost, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for rhost: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 6, service, -1, SQLITE_STATIC) != SQLITE_OK)
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
  login timestamp is in usec.
  Returns 0 on success, -1 on failure.
 */
int64_t
wtmpdb_login (const char *db_path, int type, const char *user,
	      uint64_t usec_login, const char *tty, const char *rhost,
	      const char *service, char **error)
{
  sqlite3 *db;
  int64_t retval;

  if ((db = open_database_rw (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    return -1;

  retval = add_entry (db, type, user, usec_login, tty, rhost, service, error);

  sqlite3_close (db);

  return retval;
}

/* Updates logout field.
   logout timestamp is in usec.
   Returns 0 on success, -1 on failure. */
static int
update_logout (sqlite3 *db, int64_t id, uint64_t usec_logout, char **error)
{
  sqlite3_stmt *res;
  char *sql = "UPDATE wtmp SET Logout = ? WHERE ID = ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, usec_logout) != SQLITE_OK)
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
        if (asprintf (error, "Failed to create update query (ID): %s",
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
  logout timestamp is in usec.
  ID is the return value of wtmpdb_login/logwtmpdb.
  Returns 0 on success, -1 on failure.
 */
int
wtmpdb_logout (const char *db_path, int64_t id, uint64_t usec_logout,
	       char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_rw (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    return -1;

  retval = update_logout (db, id, usec_logout, error);

  sqlite3_close (db);

  return retval;
}

static int64_t
search_id (sqlite3 *db, const char *tty, char **error)
{
  int64_t id = -1;
  sqlite3_stmt *res;
  char *sql = "SELECT ID FROM wtmp WHERE TTY = ? AND Logout IS NULL ORDER BY Login DESC LIMIT 1";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("Out of memory");

      return -1;
    }

  if (sqlite3_bind_text (res, 1, tty, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create search query: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    id = sqlite3_column_int64 (res, 0);
  else
    {
      if (error)
        if (asprintf (error, "TTY '%s' without logout time not found (%d)", tty, step) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize (res);
      return -1;
    }

  sqlite3_finalize (res);

  return id;
}

int64_t
wtmpdb_get_id (const char *db_path, const char *tty, char **error)
{
  sqlite3 *db;
  int retval;

  if ((db = open_database_ro (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    return -1;

  retval = search_id (db, tty, error);

  sqlite3_close (db);

  return retval;
}

/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, -1 on failure. */
int
wtmpdb_read_all  (const char *db_path,
		  int (*cb_func)(void *unused, int argc, char **argv,
				 char **azColName),
		  char **error)
{
  sqlite3 *db;
  char *err_msg = 0;

  if ((db = open_database_ro (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    return -1;

  char *sql = "SELECT * FROM wtmp ORDER BY Login DESC";

  if (sqlite3_exec (db, sql, cb_func, NULL, &err_msg) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "SQL error: %s", err_msg) < 0)
          *error = strdup ("Out of memory");

      sqlite3_free (err_msg);
      sqlite3_close (db);
      return -1;
    }

  sqlite3_close (db);

  return 0;
}

static int
export_row( sqlite3 *db_dest, sqlite3_stmt *sqlStatement, char **error ) {
  char *endptr;

  const int type = sqlite3_column_int( sqlStatement, 1 );
  const char *user = (const char*)sqlite3_column_text( sqlStatement, 2 );
  const char *tty = (const char*)sqlite3_column_text( sqlStatement, 5 );
  const char *host = (const char*)sqlite3_column_text( sqlStatement, 6 );
  const char *service = (const char*)sqlite3_column_text( sqlStatement, 7 );
  uint64_t login_t = strtoul((const char*)sqlite3_column_text( sqlStatement, 3 ), &endptr, 10);
  if ((errno == ERANGE && login_t == UINT64_MAX)
      || (endptr == (const char *)sqlite3_column_text( sqlStatement, 3 )) || (*endptr != '\0'))
    fprintf (stderr, "Invalid numeric time entry for 'login': '%s'\n",
	     sqlite3_column_text( sqlStatement, 5 ));

  int id = add_entry (db_dest,
		      type,
		      user,
		      login_t,
		      tty,
		      host,
		      service,
		      error);
  if (id >=0)
    {
      const char *logout = (const char*)sqlite3_column_text( sqlStatement, 4 );
      if (logout)
	{
          int64_t logout_t = strtoul(logout, &endptr, 10);
	  if ((errno == ERANGE && logout_t == INT64_MAX)
	      || (endptr == logout) || (*endptr != '\0'))
	  {
	    fprintf (stderr, "Invalid numeric time entry for 'logout': '%s'\n", sqlite3_column_text( sqlStatement, 3 ));
	    return -1;
	  }
          if (update_logout (db_dest, id, logout_t, error) == -1)
	  {
            fprintf (stderr, "Cannot update DB value: '%s'\n", *error);
	    return -1;
	  }
	}
    }
  else
    {
       fprintf (stderr, "Cannot insert DB value: '%s'\n", *error);
       return -1;
    }

   return 0;
}

/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, -1 on failure. */
int
wtmpdb_logrotate  (const char *db_path,
		   const int days,
		   char **error)
{
  sqlite3 *db_src;
  sqlite3 *db_dest;
  struct timespec ts_now;
  clock_gettime (CLOCK_REALTIME, &ts_now);
  time_t rawtime = time(0); // System time: number of seconds since 00:00, Jan 1 1970 UTC
  time(&rawtime);
  struct tm *tm = localtime (&rawtime);
  uint64_t login_t = (ts_now.tv_sec - days * 86400) * USEC_PER_SEC;
  char date[10];
  strftime (date, 10, "%Y%m%d", tm);

  char *dest_path = NULL;
  char *dest_file = strdup(db_path);
  strip_extension(dest_file);
  if (asprintf (&dest_path, "%s/%s_%s.db", dirname(dest_file), basename(dest_file), date) < 0)
    {
      *error = strdup ("Out of memory");
      return -1;
    }
  if ((db_dest = open_database_rw (dest_path, error)) == NULL)
    {
      free(dest_path);
      free(dest_file);
      return -1;
    }

  if ((db_src = open_database_rw (db_path?db_path:_PATH_WTMPDB, error)) == NULL)
    {
      free(dest_path);
      free(dest_file);
      sqlite3_close (db_dest);
      return -1;
    }

  char *sql_select = "SELECT * FROM wtmp where Login <= ?";
  sqlite3_stmt *res;
  if (sqlite3_prepare_v2 (db_src, sql_select, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup ("Out of memory");
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, login_t) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  int rc;
  while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
    export_row( db_dest, res, error );
  }
  if (rc != SQLITE_DONE) {
    if (asprintf (error, "SQL error: %s", sqlite3_errmsg(db_src)) < 0)
      *error = strdup ("Out of memory");

    sqlite3_finalize(res);
    sqlite3_close (db_src);
    sqlite3_close (db_dest);
    free(dest_path);
    free(dest_file);
    return -1;
  }

  sqlite3_finalize(res);

  char *sql_delete = "DELETE FROM wtmp where Login <= ?";
  if (sqlite3_prepare_v2 (db_src, sql_delete, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to execute statement: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup ("Out of memory");
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, login_t) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup("Out of memory");

      sqlite3_finalize(res);
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
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
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  sqlite3_finalize(res);
  sqlite3_close (db_src);
  sqlite3_close (db_dest);
  free(dest_path);
  free(dest_file);

  return 0;
}
