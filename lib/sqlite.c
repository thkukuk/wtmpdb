/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, 2024 Thorsten Kukuk <kukuk@suse.com>

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

#include "config.h"

#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "wtmpdb.h"
#include "sqlite.h"
#include "mkdir_p.h"

#define TIMEOUT 5000 /* 5 sec */

static void
strip_extension(char *in_str)
{
    static const int name_min_len = 1;
    static const int max_ext_len = 4;

    /* Check chars starting at end of string to find last '.' */
    for (size_t i = strlen(in_str); i > (name_min_len + max_ext_len); i--)
    {
        if (in_str[i] == '.')
        {
            in_str[i] = '\0';
            return;
        }
    }
}

static int
open_database_ro (const char *path, sqlite3 **db, char **error)
{
  int r;

  r = sqlite3_open_v2 (path, db, SQLITE_OPEN_READONLY, NULL);
  if (r != SQLITE_OK)
    {
      if (error)
	if (asprintf(error, "open_database_ro: Cannot open database (%s): %s",
		     path, sqlite3_errmsg(*db)) < 0)
	  *error = strdup("open_database_ro: Out of memory");
      sqlite3_close(*db);
      *db = NULL;
      return r;
    }

  sqlite3_busy_timeout(*db, TIMEOUT);

  return 0;
}

static int
open_database_rw (const char *path, sqlite3 **db, char **error)
{
  int r;

  char *buf = strdup(path);
  mkdir_p(dirname(buf), 0755);
  free(buf);

#if WITH_WTMPDBD
  mode_t old_umask = umask(0077);
#endif

  r = sqlite3_open (path, db);
#if WITH_WTMPDBD
  umask (old_umask);
#endif
  if (r != SQLITE_OK)
    {
      if (error)
	if (asprintf (error, "open_database_rw: Cannot create/open database (%s): %s",
		      path, sqlite3_errmsg (*db)) < 0)
	  *error = strdup ("open_database_rw: Out of memory");

      sqlite3_close (*db);
      *db = NULL;
      return -r;
    }

  sqlite3_busy_timeout(*db, TIMEOUT);

  return 0;
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
	if (asprintf (error, "add_entry: SQL error: %s", err_msg) < 0)
	  *error = strdup ("add_entry: Out of memory");
      sqlite3_free (err_msg);

      return -1;
    }

  if (sqlite3_prepare_v2 (db, sql_insert, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("add_entry: Out of memory");

      return -1;
    }

  if (sqlite3_bind_int (res, 1, type) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for type: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 2, user, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for user: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("add_entry: Out of memory");

      sqlite3_finalize (res);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 3, usec_login) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 4, tty, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for tty: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 5, rhost, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for rhost: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_text (res, 6, service, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "add_entry: Failed to create replace statement for service: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step != SQLITE_DONE)
    {
      if (error)
        if (asprintf (error, "add_entry: Adding an entry did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("add_entry: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  sqlite3_finalize(res);

  return sqlite3_last_insert_rowid(db);
}

/*
  Add new wtmp entry to db.
  login timestamp is in usec.
  Returns ID on success, < 0 on failure.
 */
int64_t
sqlite_login(const char *db_path, int type, const char *user,
	     uint64_t usec_login, const char *tty, const char *rhost,
	     const char *service, char **error)
{
  sqlite3 *db;
  int64_t id;
  int r;

  r = open_database_rw(db_path, &db, error);
  if (r < 0)
    return r;

  id = add_entry(db, type, user, usec_login, tty, rhost, service, error);

  sqlite3_close(db);

  return id;
}

/* Updates logout field.
   logout timestamp is in usec.
   Returns 0 on success, < 0 on failure. */
static int
update_logout (sqlite3 *db, int64_t id, uint64_t usec_logout, char **error)
{
  sqlite3_stmt *res;
  char *sql = "UPDATE wtmp SET Logout = ? WHERE ID = ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "update_logout: Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("update_logout: Out of memory");

      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, usec_logout) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "update_logout: Failed to create update query (logout): %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("update_logout: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 2, id) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "update_logout: Failed to create update query (ID): %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup("update_logout: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int step = sqlite3_step (res);

  if (step != SQLITE_DONE)
    {
      if (error)
        if (asprintf (error, "update_logout: Updating logout time did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("update_logout: Out of memory");

      sqlite3_finalize(res);
      return -1;
    }

  int changes;
  if ((changes = sqlite3_changes (db)) != 1)
    {
      if (error)
        if (asprintf (error, "update_logout: Updated wrong number of rows, expected 1, got %d",
                      changes) < 0)
          *error = strdup("update_logout: Out of memory");

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
  Returns 0 on success, < 0 on failure.
 */
int
sqlite_logout (const char *db_path, int64_t id, uint64_t usec_logout,
	       char **error)
{
  sqlite3 *db;
  int r;

  r = open_database_rw (db_path, &db, error);
  if (r < 0)
    return r;

  r = update_logout(db, id, usec_logout, error);

  sqlite3_close (db);

  return r;
}

static int64_t
search_id (sqlite3 *db, const char *tty, char **error)
{
  int64_t id = -1;
  sqlite3_stmt *res;
  char *sql = "SELECT ID FROM wtmp WHERE TTY = ? AND Logout IS NULL ORDER BY Login DESC LIMIT 1";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      int r = -ENOTSUP;
      if (error)
        if (asprintf (error, "search_id: Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
	  {
	    r = -ENOMEM;
	    *error = strdup ("search_id: Out of memory");
	  }
      return r;
    }

  if (sqlite3_bind_text (res, 1, tty, -1, SQLITE_STATIC) != SQLITE_OK)
    {
      int r = -EPROTO;
      if (error)
        if (asprintf (error, "search_id: Failed to create search query: %s",
                      sqlite3_errmsg (db)) < 0)
	  {
	    r = -ENOMEM;
	    *error = strdup("search_id: Out of memory");
	  }

      sqlite3_finalize(res);
      return r;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    id = sqlite3_column_int64 (res, 0);
  else if (step == SQLITE_DONE)
    {
      id = -ENOENT;
      if (error)
        if (asprintf (error, "search_id: Open entry for tty '%s' not found", tty) < 0)
	  {
	    *error = strdup("search_id: Out of memory");
	    id = -ENOMEM;
	  }
    }
  else
    {
      id = -ENOENT;
      if (error)
        if (asprintf (error, "search_id: sqlite3_step returned: %d", step) < 0)
	  {
	    *error = strdup("search_id: Out of memory");
	    id = -ENOMEM;
	  }
    }

  sqlite3_finalize (res);

  return id;
}

int64_t
sqlite_get_id (const char *db_path, const char *tty, char **error)
{
  sqlite3 *db;
  int64_t retval;
  int r;

  r = open_database_ro (db_path, &db, error);
  if (r != 0)
    return -r;

  retval = search_id (db, tty, error);

  sqlite3_close (db);

  return retval;
}

/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, -1 on failure. */
int
sqlite_read_all (const char *db_path,
		 int (*cb_func)(void *unused, int argc, char **argv,
				char **azColName),
		 void *userdata, char **error)
{
  sqlite3 *db;
  char *err_msg = 0;
  int r;

  r = open_database_ro (db_path, &db, error);
  if (r != 0)
    return -r;

  char *sql = "SELECT * FROM wtmp ORDER BY Login DESC, Logout ASC";

  r = sqlite3_exec (db, sql, cb_func, userdata, &err_msg);
  sqlite3_close (db);
  if (r != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "sqlite_read_all: SQL error: %s", err_msg) < 0)
          *error = strdup ("sqlite_read_all: Out of memory");

      sqlite3_free (err_msg);
      return -r;
    }

  return 0;
}

static int
export_row (sqlite3 *db_dest, sqlite3_stmt *sqlStatement, char **error)
{
  char *endptr;

  const int type = sqlite3_column_int( sqlStatement, 1 );
  const char *user = (const char*)sqlite3_column_text( sqlStatement, 2 );
  const char *tty = (const char*)sqlite3_column_text( sqlStatement, 5 );
  const char *host = (const char*)sqlite3_column_text( sqlStatement, 6 );
  const char *service = (const char*)sqlite3_column_text( sqlStatement, 7 );
  uint64_t login_t = strtoul((const char*)sqlite3_column_text( sqlStatement, 3 ), &endptr, 10);
  if ((errno == ERANGE && login_t == UINT64_MAX)
      || (endptr == (const char *)sqlite3_column_text( sqlStatement, 3 )) || (*endptr != '\0'))
    fprintf (stderr, "export_row: Invalid numeric time entry for 'login': '%s'\n",
	     sqlite3_column_text( sqlStatement, 5 ));

  int64_t id = add_entry (db_dest, type, user, login_t, tty, host,
			  service, error);
  if (id >=0)
    {
      const char *logout = (const char*)sqlite3_column_text( sqlStatement, 4 );
      if (logout)
	{
          uint64_t logout_t = strtoul(logout, &endptr, 10);
	  if ((errno == ERANGE && logout_t == INT64_MAX)
	      || (endptr == logout) || (*endptr != '\0'))
	  {
	    fprintf (stderr, "export_row: Invalid numeric time entry for 'logout': '%s'\n", sqlite3_column_text( sqlStatement, 3 ));
	    return -1;
	  }
          if (update_logout (db_dest, id, logout_t, error) == -1)
	  {
            fprintf (stderr, "export_row: Cannot update DB value: '%s'\n", *error);
	    return -1;
	  }
	}
    }
  else
    {
       fprintf (stderr, "export_row: Cannot insert DB value: '%s'\n", *error);
       return -1;
    }

  return 0;
}

/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, <0 on failure. */
int
sqlite_rotate(const char *db_path, const int days, char **wtmpdb_name,
	      uint64_t *entries, char **error)
{
  sqlite3 *db_src;
  sqlite3 *db_dest;
  uint64_t counter = 0;
  struct timespec threshold;
  clock_gettime (CLOCK_REALTIME, &threshold);
  threshold.tv_sec -= days * 86400;
  struct tm *tm = localtime (&threshold.tv_sec);
  uint64_t login_t = wtmpdb_timespec2usec (threshold);
  char date[10];
  strftime (date, 10, "%Y%m%d", tm);
  char *dest_path = NULL;
  char *dest_file = strdup(db_path);
  int r;

  strip_extension(dest_file);

  if (asprintf (&dest_path, "%s/%s_%s.db", dirname(dest_file), basename(dest_file), date) < 0)
    {
      *error = strdup ("sqlite_rotate: Out of memory");
      return -ENOMEM;
    }

  r = open_database_rw(dest_path, &db_dest, error);
  if (r < 0)
    {
      free(dest_path);
      free(dest_file);
      return r;
    }

  r = open_database_rw (db_path, &db_src, error);
  if (r < 0)
    {
      free(dest_path);
      free(dest_file);
      sqlite3_close (db_dest);
      return r;
    }

  char *sql_select = "SELECT * FROM wtmp where Login <= ?";
  sqlite3_stmt *res;
  if (sqlite3_prepare_v2 (db_src, sql_select, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "sqlite_rotate: Failed to execute statement %s: %s",
		      sql_select,
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup ("sqlite_rotate: Out of memory");
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, login_t) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "sqlite_rotate: Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup("sqlite_rotate: Out of memory");

      sqlite3_finalize(res);
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  int rc;
  while ((rc = sqlite3_step(res)) == SQLITE_ROW) {
    export_row (db_dest, res, error);
    ++counter;
  }
  if (rc != SQLITE_DONE)
    {
      if (asprintf (error, "sqlite_rotate: SQL error: %s", sqlite3_errmsg(db_src)) < 0)
	*error = strdup ("sqlite_rotate: Out of memory");

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
        if (asprintf (error, "sqlite_rotate: Failed to execute statement %s: %s",
		      sql_delete,
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup ("sqlite_rotate: Out of memory");
      sqlite3_close (db_src);
      sqlite3_close (db_dest);
      free(dest_path);
      free(dest_file);
      return -1;
    }

  if (sqlite3_bind_int64 (res, 1, login_t) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "sqlite_rotate: Failed to create replace statement for login time: %s",
                      sqlite3_errmsg (db_src)) < 0)
          *error = strdup("sqlite_rotate: Out of memory");

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
        if (asprintf (error, "sqlite_rotate: Adding an entry did not return SQLITE_DONE: %d",
                      step) < 0)
          *error = strdup("sqlite_rotate: Out of memory");

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

  if (counter > 0)
    {
      if (wtmpdb_name)
	*wtmpdb_name = strdup (dest_path);
      if (entries)
	*entries = counter;
    }
  else
    unlink (dest_path);

  free(dest_path);
  free(dest_file);

  return 0;
}

static uint64_t
search_boottime (sqlite3 *db, char **error)
{
  uint64_t boottime = 0;
  sqlite3_stmt *res;
  char *sql = "SELECT Login FROM wtmp WHERE User = 'reboot' ORDER BY Login DESC LIMIT 1;";

  if (sqlite3_prepare_v2 (db, sql, -1, &res, 0) != SQLITE_OK)
    {
      if (error)
        if (asprintf (error, "search_boottime: Failed to execute statement: %s",
                      sqlite3_errmsg (db)) < 0)
          *error = strdup ("search_boottime: Out of memory");

      return 0;
    }

  int step = sqlite3_step (res);

  if (step == SQLITE_ROW)
    boottime = (uint64_t)sqlite3_column_int64 (res, 0);
  else
    {
      if (error)
        if (asprintf (error, "search_boottime: Boot time not found (%d)", step) < 0)
          *error = strdup("search_boottime: Out of memory");

      sqlite3_finalize (res);
      return 0;
    }

  sqlite3_finalize (res);

  return boottime;
}

int
sqlite_get_boottime (const char *db_path,
		     uint64_t *boottime, char **error)
{
  sqlite3 *db;
  int r;

  r = open_database_ro (db_path, &db, error);
  if (r != 0)
    return -r;

  *boottime = search_boottime (db, error);

  sqlite3_close (db);

  return 0;
}
