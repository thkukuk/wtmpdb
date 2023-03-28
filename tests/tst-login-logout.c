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

int
main(void)
{
  const char *db_path = "tst-login-logout.db";

  /* make sure there is no old stuff flying around */
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

  return 0;
}
