/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2024, 2025 Thorsten Kukuk <kukuk@suse.com>

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
   Create login entry, search for ID, add logout time, get boottime.
*/

#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "basics.h"
#include "wtmpdb.h"

static void
format_time (char *dst, size_t dstlen, uint64_t time)
{
  time_t t = (time_t)time;
  snprintf (dst, dstlen, "%s", ctime (&t));
  dst[strlen (dst)-1] = '\0'; /* Remove trailing '\n' */
}

int
main(void)
{
  const char *user = "wtmpdb-test";
  const char *tty = "ttyX";
  const char *rhost = "remote-host";
  const char *service = "sshd";
  char *error = NULL;
  int64_t id;
  struct timespec ts;
  uint64_t login_t;
  uint64_t logout_t;

  if (getuid() != 0)
    return 77;

  clock_gettime (CLOCK_REALTIME, &ts);
  login_t = wtmpdb_timespec2usec (ts);

  if ((id = wtmpdb_login ("varlink", USER_PROCESS, user,
			  login_t, tty, rhost, service, &error)) < 0)
    {
      if (error)
        {
          fprintf (stderr, "wtmpdb_login: %s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_login failed (%" PRId64 ")\n", id);

      if (id == -ECONNREFUSED || id == -ENOENT ||
	  id == -EACCES || id == -EPROTONOSUPPORT)
	return 77;

      return 1;
    }
  printf ("wtmpdb_login id: %" PRId64 "\n", id);

  /* wtmpdb_get_id should return the same ID as wtmpdb_login */
  int64_t newid;
  if ((newid = wtmpdb_get_id ("varlink", tty, &error)) < 0)
    {
      if (error)
        {
          fprintf (stderr, "wtmpdb_get_id: %s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_get_id failed\n");
      return 1;
    }
  printf ("wtmpdb_get_id: %" PRId64 "\n", newid);

  if (newid != id)
    {
      fprintf (stderr, "IDs don't match: %" PRId64 " != %" PRId64 "\n", id, newid);
      return 1;
    }

  clock_gettime (CLOCK_REALTIME, &ts);
  logout_t = wtmpdb_timespec2usec (ts);

  if (wtmpdb_logout ("varlink", id, logout_t, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "wtmpdb_logout: %s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_logout failed\n");
      return 1;
    }

  uint64_t boottime = wtmpdb_get_boottime ("varlink", &error);
  if (boottime == 0 || error != NULL)
    {
      if (error)
        {
          fprintf (stderr, "wtmpdb_get_boottime: %s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_get_boottime failed\n");
      return 1;
    }
  else
    {
      char timebuf[32];
      format_time (timebuf, sizeof (timebuf), boottime/USEC_PER_SEC);

      printf ("wtmpdb_get_boottime: %s\n", timebuf);
    }

  _cleanup_(freep) char *backup = NULL;
  uint64_t entries = 0;
  if (wtmpdb_rotate ("varlink", 30, &error, &backup, &entries) < 0)
    {
      if (error)
        {
          fprintf (stderr, "wtmpdb_rotate: %s\n", error);
          free (error);
        }
      else
	fprintf (stderr, "wtmpdb_rotate failed\n");
      return 1;
    }
  else if (entries == 0)
    printf ("Nothing to move for wtmpdb_rotate\n");
  else
    printf ("wtmpdb_rotate moved %" PRIu64 " entries into %s\n", entries, backup);

  return 0;
}
