/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, 2025 Thorsten Kukuk <kukuk@suse.com>

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
#include "basics.h"

#include "wtmpdb.h"

static int
test_args (const char *db_path, const char *user, const char *tty,
	   const char *rhost, const char *service, const int days)
{
  char *error = NULL;
  int64_t id;
  struct timespec ts;
  uint64_t login_t;
  uint64_t logout_t;

  clock_gettime (CLOCK_REALTIME, &ts);
  ts.tv_sec -= 86400 * days;
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
test_rotate (const char *db_path, const int days)
{
  int expected;
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
  expected = (days-1) * 5;
  if (counter != expected)
    {
      fprintf (stderr, "wtmpdb_read_all returned %d expected %d\n", counter, expected);
      return 1;
    }

  if (wtmpdb_rotate (db_path, days, &error, NULL, NULL) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_rotate failed\n");
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
  expected = (days-2) * 5;
  if (counter != expected)
    {
      fprintf (stderr, "wtmpdb_read_all returned %d expected %d\n", counter, expected);
      return 1;
    }

  return 0;
}

static void
remove_backup_db(int days)
{
  _cleanup_(freep) char *backup_path = NULL;
  struct timespec ts_now;

  clock_gettime (CLOCK_REALTIME, &ts_now);

  time_t offset = ts_now.tv_sec - days * 86400;
  struct tm *tm = localtime (&offset);
  char date[10];
  strftime (date, 10, "%Y%m%d", tm);

  if (asprintf (&backup_path, "tst-login-logout_%s.db", date) < 0)
    {
      fprintf (stderr, "Out of memory");
      return;
    }
  remove (backup_path);
}

int
main(void)
{
  const char *db_path = "tst-login-logout.db";

  /* make sure there is no old stuff flying around. The backup file is not so important. */
  remove (db_path);

  if (test_args (db_path, "user1", "test-tty", "localhost", NULL, 3) != 0)
    return 1;
  if (test_args (db_path, "user2", NULL, NULL, NULL, 3) != 0)
    return 1;
  if (test_args (db_path, "user3", NULL, NULL, NULL, 3) != 0)
    return 1;
  if (test_args (db_path, "user4", "test-tty", NULL, NULL, 3) != 0)
    return 1;
  if (test_args (db_path, "user5", NULL, "localhost", NULL, 3) != 0)
    return 1;

  if (test_args (db_path, "user1", "test-tty", "localhost", NULL, 2) != 0)
    return 1;
  if (test_args (db_path, "user2", NULL, NULL, NULL, 2) != 0)
    return 1;
  if (test_args (db_path, "user3", NULL, NULL, NULL, 2) != 0)
    return 1;
  if (test_args (db_path, "user4", "test-tty", NULL, NULL, 2) != 0)
    return 1;
  if (test_args (db_path, "user5", NULL, "localhost", NULL, 2) != 0)
    return 1;

  if (test_rotate (db_path, 3) != 0)
    return 1;

  if (test_rotate (db_path, 2) != 0)
    return 1;

  /* cleanup */
  remove_backup_db(2);
  remove_backup_db(3);
  remove (db_path);

  return 0;
}
