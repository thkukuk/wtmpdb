/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2025, Andrew Bower <andrew@bower.uk>

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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <utmp.h>

enum utmp_type {
  UTMP_EMPTY = EMPTY,
  UTMP_RUN_LVL = RUN_LVL,
  UTMP_BOOT_TIME = BOOT_TIME,
  UTMP_USER_PROCESS = USER_PROCESS,
  UTMP_DEAD_PROCESS = DEAD_PROCESS,
};

#undef EMPTY
#undef RUN_LVL
#undef BOOT_TIME
#undef USER_PROCESS

#include "wtmpdb.h"
#include "import.h"

/* Import utmp entries from memory into a wtmpdb-format database.
   Returns 0 on success, -1 on failure. */
static int
import_utmp_records (const char *db_path,
		     const struct utmp *utmp_data,
		     int entries,
		     char **error)
{
  int64_t last_reboot_id = -1;
  int64_t *id_map;
  int row = 0;
  int ret = 0;

  id_map = calloc (entries, sizeof *id_map);
  if (id_map == NULL)
    {
      *error = strdup ("wtmpdb_import: out of memory allocating id map");
      return -1;
    }

  for (row = 0; ret == 0 && row < entries; row++)
    {
      const struct utmp *u = utmp_data + row;
      const struct utmp *v;
      int64_t id = -1;
      int64_t usecs = USEC_PER_SEC * u->ut_tv.tv_sec + u->ut_tv.tv_usec;

      switch (u->ut_type)
	{
	case UTMP_RUN_LVL:
	case UTMP_BOOT_TIME:
	  if (u->ut_id[0] == '~' &&
	      u->ut_id[1] == '~' &&
	      u->ut_id[2] == '\0')
	    {
	      if (strcmp (u->ut_user, "reboot") == 0)
		{
		  id = wtmpdb_login (db_path, BOOT_TIME, "reboot", usecs, "~",
				     u->ut_host, NULL, error);
		  ret = id == -1 ? -1 : 0;
		  last_reboot_id = id;
		}
	      else if (strcmp (u->ut_user, "shutdown") == 0 &&
		       last_reboot_id != -1)
		{
		  ret = wtmpdb_logout (db_path, last_reboot_id, usecs, error);
		  last_reboot_id = -1;
		}
	    }
	  break;
	case UTMP_USER_PROCESS:
	  id = wtmpdb_login (db_path, USER_PROCESS, u->ut_user, usecs,
			     u->ut_line, u->ut_host, NULL, error);
	  ret = id == -1 ? -1 : 0;
	  break;
	case UTMP_DEAD_PROCESS:
	  for (v = u - 1; v >= utmp_data && v->ut_type != UTMP_BOOT_TIME; v--)
	    {
	      if (v->ut_type == UTMP_USER_PROCESS &&
		  ((u->ut_pid != 0 && v->ut_pid == u->ut_pid) ||
		   (u->ut_pid == 0 && strncmp (v->ut_line, u->ut_line, UT_LINESIZE) == 0)))
		{
		  id = id_map[v - utmp_data];
		  if (id > 0)
		    ret = wtmpdb_logout (db_path, id, usecs, error);
		  break;
		}
	    }
	  break;
	}

      id_map[row] = id;
    }

  free (id_map);

  return ret;
}

/* Import a wtmp log file into a wtmpdb-format database.
   Returns 0 on success, -1 on failure. */
int
import_wtmp_file (const char *db_path,
		  const char *file)
{
  struct stat statbuf;
  char *error = NULL;
  const ssize_t record_sz = sizeof(struct utmp);
  ssize_t file_sz;
  ssize_t entries;
  void *data;
  int fd;
  int rc;

  fd = open (file, O_RDONLY);
  if (fd == -1)
    {
      fprintf (stderr, "Couldn't open '%s' to import: %s\n",
	       file, strerror (errno));
      return -1;
    }

  rc = fstat (fd, &statbuf);
  if (rc == -1)
    {
      fprintf (stderr, "Could not stat '%s': %s\n",
	      file, strerror (errno));
      close (fd);
      return -1;
    }

  file_sz = statbuf.st_size;
  entries = file_sz / record_sz;
  if (entries * record_sz != file_sz)
    {
      fprintf (stderr, "Warning: utmp-format file is not a multiple of "
		       "sizeof(struct utmp) in length: %zd spare bytes, %s\n",
	       file_sz - entries * record_sz, file);
    }

  data = mmap (NULL, file_sz, PROT_READ, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED)
    {
      fprintf (stderr, "Could not map file to import: %s\n", strerror (errno));
      close (fd);
      return -1;
    }

  rc = import_utmp_records (db_path, data, entries, &error);
  if (rc == -1)
    {
      fprintf (stderr, "Error importing %s: %sn", file, error);
      free(error);
    }

  munmap (data, file_sz);
  close (fd);
  return rc;
}
