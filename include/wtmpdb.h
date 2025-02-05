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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#define _PATH_WTMPDB "/var/lib/wtmpdb/wtmp.db"

#define _VARLINK_WTMPDB_SOCKET_DIR "/run/wtmpdb"
#define _VARLINK_WTMPDB_SOCKET _VARLINK_WTMPDB_SOCKET_DIR"/socket"

#define EMPTY           0  /* No valid user accounting information.  */
#define BOOT_TIME       1  /* Time of system boot.  */
#define RUNLEVEL        2  /* The system's runlevel. Unused with systemd. */
#define USER_PROCESS    3  /* Normal process.  */

#define USEC_INFINITY ((uint64_t) UINT64_MAX)
#define NSEC_PER_USEC ((uint64_t) 1000ULL)
#define USEC_PER_SEC  ((uint64_t) 1000000ULL)

#ifdef __cplusplus
extern "C" {
#endif

extern int64_t logwtmpdb (const char *db_path, const char *tty,
		          const char *name, const char *host,
		          const char *service, char **error);
extern int64_t wtmpdb_login (const char *db_path, int type,
			     const char *user, uint64_t usec_login,
			     const char *tty, const char *rhost,
			     const char *service, char **error);
extern int wtmpdb_logout (const char *db_path, int64_t id,
			  uint64_t usec_logout, char **error);
extern int wtmpdb_read_all (const char *db_path,
		            int (*cb_func) (void *unused, int argc,
				            char **argv, char **azColName),
			    char **error);
extern int wtmpdb_read_all_v2 (const char *db_path,
			       int (*cb_func) (void *unused, int argc,
					       char **argv, char **azColName),
			       void *userdata, char **error);
extern int wtmpdb_rotate (const char *db_path, const int days, char **error,
			  char **wtmpdb_name, uint64_t *entries);

/* Returns last "BOOT_TIME" entry as usec */
extern uint64_t wtmpdb_get_boottime (const char *db_path, char **error);

/* helper function */
extern int64_t wtmpdb_get_id (const char *db_path, const char *tty,
			      char **error);
extern uint64_t wtmpdb_timespec2usec (const struct timespec ts);

#ifdef __cplusplus
}
#endif
