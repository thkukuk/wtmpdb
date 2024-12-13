/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2024, Thorsten Kukuk <kukuk@suse.com>

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
#include <stddef.h>
#include <stdlib.h>

#include "basics.h"
#include "wtmpdb.h"
#include "sqlite.h"
#include "varlink.h"

static int varlink_is_active = 1;

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
  /* we can use varlink only if no specific database is requested */
  if (varlink_is_active && db_path == NULL)
    {
      int64_t id;

      id = varlink_login (type, user, usec_login, tty, rhost,
			  service, error);
      if (id >= 0)
	return id;

      if (id == -ECONNREFUSED)
	{
	  varlink_is_active = 0;
	  *error = mfree (*error);
	}
      else
	return id; /* return the error if wtmpdbd is active */
    }

  return sqlite_login (db_path?db_path:_PATH_WTMPDB, type, user,
		       usec_login, tty, rhost, service, error);
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
  /* we can use varlink only if no specific database is requested */
  if (varlink_is_active && db_path == NULL)
    {
      int r;

      r = varlink_logout (id, usec_logout, error);
      if (r >= 0)
	return r;

      if (id == -ECONNREFUSED)
	{
	  varlink_is_active = 0;
	  *error = mfree (*error);
	}
      else
	return r; /* return the error if wtmpdbd is active */
    }

  return sqlite_logout (db_path?db_path:_PATH_WTMPDB, id, usec_logout, error);
}

int64_t
wtmpdb_get_id (const char *db_path, const char *tty, char **error)
{
  /* we can use varlink only if no specific database is requested */
  if (varlink_is_active && db_path == NULL)
    {
      int64_t id;

      id = varlink_get_id (tty, error);
      if (id >= 0)
	return id;

      if (id == -ECONNREFUSED)
	{
	  varlink_is_active = 0;
	  *error = mfree (*error);
	}
      else
	return id; /* return the error if wtmpdbd is active */
    }

  return sqlite_get_id (db_path?db_path:_PATH_WTMPDB, tty, error);
}

/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, -1 on failure. */
int
wtmpdb_read_all (const char *db_path,
		 int (*cb_func)(void *unused, int argc, char **argv,
				char **azColName),
		 char **error)
{
  return sqlite_read_all (db_path?db_path:_PATH_WTMPDB, cb_func, NULL, error);
}

int
wtmpdb_read_all_v2 (const char *db_path,
		    int (*cb_func)(void *unused, int argc, char **argv,
				   char **azColName),
		    void *userdata, char **error)
{
  return sqlite_read_all (db_path?db_path:_PATH_WTMPDB, cb_func, userdata, error);
}


/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, < 0 on failure. */
int
wtmpdb_rotate (const char *db_path, const int days, char **error,
	       char **wtmpdb_name, uint64_t *entries)
{
  /* we can use varlink only if no specific database is requested */
  if (varlink_is_active && db_path == NULL)
    {
      int r;

      r = varlink_rotate (days, wtmpdb_name, entries, error);
      if (r >= 0)
	return r;

      if (r == -ECONNREFUSED)
	{
	  varlink_is_active = 0;
	  *error = mfree (*error);
	}
      else
	return r; /* return the error if wtmpdbd is active */
    }

  return sqlite_rotate (db_path?db_path:_PATH_WTMPDB, days, wtmpdb_name, entries, error);
}

/* returns boottime entry on success or 0 in error case */
uint64_t
wtmpdb_get_boottime (const char *db_path, char **error)
{
  /* we can use varlink only if no specific database is requested */
  if (varlink_is_active && db_path == NULL)
    {
      int r;
      uint64_t boottime;

      r = varlink_get_boottime (&boottime, error);
      if (r >= 0)
	return boottime;

      if (r == -ECONNREFUSED)
	{
	  varlink_is_active = 0;
	  *error = mfree (*error);
	}
      else
	return 0; /* return the error if wtmpdbd is active */
    }

  return sqlite_get_boottime (db_path?db_path:_PATH_WTMPDB, error);
}
