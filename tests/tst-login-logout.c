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

/* Test case:
   Create login entry, add logout time.
*/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "wtmpdb.h"

static int
test_args (const char *db_path, const char *user, const char *tty,
	   const char *rhost, const char *service)
{
  char *error = NULL;
  int64_t id;
  struct timespec ts;
  int64_t login_t = -1;
  int64_t logout_t = -1;

  clock_gettime (CLOCK_REALTIME, &ts);
  ts.tv_sec -= 259200; /* three days behind */
  login_t = wtmpdb_timespec2usec (ts);

  if ((id = wtmpdb_login (db_path, USER_PROCESS, user,
			  login_t, tty, rhost, service, &error)) < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_login failed\n");
      return 1;
    }

  clock_gettime (CLOCK_REALTIME, &ts);
  logout_t = wtmpdb_timespec2usec (ts);

  if (wtmpdb_logout (db_path, id, logout_t, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_logout failed\n");
      return 1;
    }

  return 0;
}

static int counter = 0;

static int
count_entry (void *unused __attribute__((__unused__)),
	     int argc, char **argv, char **azColName)
{
  (void)argc;
  (void)argv;
  (void)azColName;
  counter++;
  return 0;
}

static int
test_logrotate (const char *db_path)
{
  char *error = NULL;

  counter = 0;
  if (wtmpdb_read_all (db_path, count_entry, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_read_all failed\n");
      return 1;
    }
  if (counter != 5)
    {
      fprintf (stderr, "wtmpdb_read_all returned %d expected 5\n", counter);
      return 1;
    }

  if (wtmpdb_logrotate (db_path, 1, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_logrotate failed\n");
      return 1;
    }

  counter = 0;
  if (wtmpdb_read_all (db_path, count_entry, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_read_all failed\n");
      return 1;
    }
  if (counter != 0)
    {
      fprintf (stderr, "wtmpdb_read_all returned %d expected 0\n", counter);
      return 1;
    }

  return 0;
}

int
main(void)
{
  const char *db_path = "tst-login-logout.db";

  /* make sure there is no old stuff flying around. The backup file is not so important. */
  remove (db_path);

  if (test_args (db_path, "user1", "test-tty", "localhost", NULL) != 0)
    return 1;
  if (test_args (db_path, "user2", NULL, NULL, NULL) != 0)
    return 1;
  if (test_args (db_path, "user3", NULL, NULL, NULL) != 0)
    return 1;
  if (test_args (db_path, "user4", "test-tty", NULL, NULL) != 0)
    return 1;
  if (test_args (db_path, "user5", NULL, "localhost", NULL) != 0)
    return 1;

  if (test_logrotate (db_path) != 0)
    return 1;

  /* cleanup */
  time_t rawtime = time(0); /* System time: number of seconds since 00:00, Jan 1 1970 UTC */
  time(&rawtime);
  struct tm *tm = localtime (&rawtime);
  char date[10];
  strftime (date, 10, "%Y%m%d", tm);
  char *backup_path = NULL;
  if (asprintf (&backup_path, "tst-login-logout_%s.db", date) < 0)
    {
      fprintf (stderr, "Out of memory");
      return 1;
    }
  remove (backup_path);
  free (backup_path);
  remove (db_path);

  return 0;
}
