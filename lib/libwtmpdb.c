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

#include <stddef.h>

#include "wtmpdb.h"
#include "sqlite.h"

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
  return sqlite_login (db_path?db_path:_PATH_WTMPDB, type, user, usec_login, tty, rhost,
		       service, error);
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
  return sqlite_logout (db_path?db_path:_PATH_WTMPDB, id, usec_logout, error);
}

int64_t
wtmpdb_get_id (const char *db_path, const char *tty, char **error)
{
  return sqlite_get_id (db_path?db_path:_PATH_WTMPDB, tty, error);
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
  return sqlite_read_all (db_path?db_path:_PATH_WTMPDB, cb_func, error);
}


/* Reads all entries from database and calls the callback function for
   each entry.
   Returns 0 on success, -1 on failure. */
int
wtmpdb_rotate (const char *db_path, const int days, char **error,
	       char **wtmpdb_name, uint64_t *entries)
{
  return sqlite_rotate (db_path, days, wtmpdb_name, entries, error);
}

uint64_t
wtmpdb_get_boottime (const char *db_path, char **error)
{
  return sqlite_get_boottime (db_path?db_path:_PATH_WTMPDB, error);
}
