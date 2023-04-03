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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "wtmpdb.h"

#define WTMPDB_DEBUG        01  /* send info to syslog(3) */
#define WTMPDB_QUIET        02  /* keep quiet about things */

static const char *wtmpdb_path = _PATH_WTMPDB;

/* From pam_inline.h
 *
 * Returns NULL if STR does not start with PREFIX,
 * or a pointer to the first char in STR after PREFIX.
 */
static inline const char *
skip_prefix (const char *str, const char *prefix)
{
  size_t prefix_len = strlen (prefix);

  return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

static const char *
get_tty (pam_handle_t *pamh, int ctrl)
{
  const void *void_str = NULL;
  const char *tty;

  int retval = pam_get_item (pamh, PAM_TTY, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL)
    tty = "";
  else
    tty = void_str;

  /* strip leading "/dev/" from tty. */
  const char *str = skip_prefix(tty, "/dev/");
  if (str != NULL)
    tty = str;

  if (ctrl & WTMPDB_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "tty=%s", tty);

  return tty;
}

static int
_pam_parse_args (pam_handle_t *pamh,
		 int flags, int argc,
		 const char **argv)
{
  int ctrl = 0;
  const char *str;

  /* does the application require quiet? */
  if (flags & PAM_SILENT)
    ctrl |= WTMPDB_QUIET;

  /* step through arguments */
  for (; argc-- > 0; ++argv)
    {
      if (strcmp (*argv, "debug") == 0)
	ctrl |= WTMPDB_DEBUG;
      else if (strcmp (*argv, "silent") == 0)
	ctrl |= WTMPDB_QUIET;
      else if ((str = skip_prefix(*argv, "database=")) != NULL)
	wtmpdb_path = str;
      else
	pam_syslog (pamh, LOG_ERR, "Unknown option: %s", *argv);
    }

  return ctrl;
}

int
pam_sm_authenticate (pam_handle_t *pamh __attribute__((__unused__)),
		     int flags __attribute__((__unused__)),
		     int argc __attribute__((__unused__)),
		     const char **argv __attribute__((__unused__)))
{
  return PAM_IGNORE;
}

int
pam_sm_setcred (pam_handle_t *pamh __attribute__((__unused__)),
		int flags __attribute__((__unused__)),
		int argc __attribute__((__unused__)),
		const char **argv __attribute__((__unused__)))
{
  return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh __attribute__((__unused__)),
		  int flags __attribute__((__unused__)),
		  int argc __attribute__((__unused__)),
		  const char **argv __attribute__((__unused__)))
{
  return PAM_IGNORE;
}

static void
free_idptr(pam_handle_t *pamh __attribute__((__unused__)), void *idptr,
	   int error_status __attribute__((__unused__)))
{
  free (idptr);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  const struct passwd *pwd;
  const void *void_str;
  const char *user;
  const char *tty;
  const char *rhost;
  const char *service;
  char *error = NULL;
  int ctrl;
  int64_t id;

  ctrl = _pam_parse_args (pamh, flags, argc, argv);

  void_str = NULL;
  int retval = pam_get_item (pamh, PAM_USER, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL || strlen (void_str) == 0)
    {
      if (!(ctrl & WTMPDB_QUIET))
	pam_syslog (pamh, LOG_NOTICE, "User unknown");
      return PAM_USER_UNKNOWN;
    }
  user = void_str;

  /* verify the user exists */
  pwd = pam_modutil_getpwnam (pamh, user);
  if (pwd == NULL)
    {
      if (ctrl & WTMPDB_DEBUG)
	pam_syslog (pamh, LOG_DEBUG, "Couldn't find user %s",
		    (const char *)user);
      return PAM_USER_UNKNOWN;
    }

  if (ctrl & WTMPDB_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "user=%s", user);

  tty = get_tty (pamh, ctrl);

  void_str = NULL;
  retval = pam_get_item (pamh, PAM_RHOST, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL)
    {
      void_str = NULL;
      retval = pam_get_item (pamh, PAM_XDISPLAY, &void_str);
      if (retval != PAM_SUCCESS || void_str == NULL)
	rhost = "";
      else
	{
	  rhost = void_str;
	  if (ctrl & WTMPDB_DEBUG)
	    pam_syslog (pamh, LOG_DEBUG, "rhost(PAM_XDISPLAY)=%s", rhost);
	}
    }
  else
    {
      rhost = void_str;
      if (ctrl & WTMPDB_DEBUG)
	pam_syslog (pamh, LOG_DEBUG, "rhost(PAM_RHOST)=%s", rhost);
    }

  void_str = NULL;
  retval = pam_get_item (pamh, PAM_SERVICE, &void_str);
  if (retval != PAM_SUCCESS || void_str == NULL)
    service = "";
  else
    service = void_str;
  if (ctrl & WTMPDB_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "service=%s", service);

  if ((id = logwtmpdb (wtmpdb_path, tty, user, rhost, service, &error)) < 0)
    {
      if (error)
        {
          pam_syslog (pamh, LOG_ERR, "%s", error);
          free (error);
        }
      else
        pam_syslog (pamh, LOG_ERR,
		    "Unknown error writing to database %s", wtmpdb_path);

      return PAM_SYSTEM_ERR;
    }

  if (ctrl & WTMPDB_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "id=%lld", (long long int)id);

  int64_t *idptr = calloc (1, sizeof(int64_t));
  *idptr = id;

  pam_set_data(pamh, "ID", idptr, free_idptr);

  return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
  char *error = NULL;
  int ctrl = _pam_parse_args (pamh, flags, argc, argv);
  const void *voidptr = NULL;
  const int64_t *idptr;
  int retval;
  struct timespec ts;

  clock_gettime (CLOCK_REALTIME, &ts);

  if ((retval = pam_get_data (pamh, "ID", &voidptr)) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot get ID from open session!");
      return retval;
    }
  idptr = voidptr;
  int64_t id = *idptr;

  if (ctrl & WTMPDB_DEBUG)
    pam_syslog (pamh, LOG_DEBUG, "id=%lli", (long long int)id);

  if (wtmpdb_logout (wtmpdb_path, id, wtmpdb_timespec2usec (ts), &error) < 0)
    {
      if (error)
        {
          pam_syslog (pamh, LOG_ERR, "%s", error);
          free (error);
        }
      else
        pam_syslog (pamh, LOG_ERR,
		    "Unknown error writing logout time to database %s",
		    wtmpdb_path);

      return PAM_SYSTEM_ERR;
    }

  return PAM_SUCCESS;
}
