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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "wtmpdb.h"

uint64_t
wtmpdb_timespec2usec (const struct timespec ts)
{
  if (ts.tv_sec < 0 || ts.tv_nsec < 0)
    return USEC_INFINITY;

  if ((uint64_t) ts.tv_sec >
      (UINT64_MAX - (ts.tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
    return UINT64_MAX;

  return (uint64_t) ts.tv_sec * USEC_PER_SEC +
    (uint64_t) ts.tv_nsec / NSEC_PER_USEC;
}


int64_t
logwtmpdb (const char *db_path, const char *tty, const char *name,
	   const char *host, const char *service, char **error)
{
  int64_t retval = -1;
  struct timespec ts;

  clock_gettime (CLOCK_REALTIME, &ts);

  uint64_t time = wtmpdb_timespec2usec (ts);

  if (error)
    *error = NULL;

  if (name != NULL && strlen (name) > 0)
    { /* login */
      retval = wtmpdb_login (db_path, USER_PROCESS, name, time, tty,
		      	     host, service, error);
    }
  else
    { /* logout */
      int64_t id = wtmpdb_get_id (db_path, tty, error);
      retval = wtmpdb_logout (db_path, id, time, error);
    }

  return retval;
}
