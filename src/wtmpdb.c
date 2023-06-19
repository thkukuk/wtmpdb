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

#include "config.h"

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <sys/utsname.h>

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#include "wtmpdb.h"

static char *wtmpdb_path = _PATH_WTMPDB;

#define TIMEFMT_CTIME 1
#define TIMEFMT_SHORT 2
#define TIMEFMT_HHMM  3

#define LOGROTATE_DAYS 60

static uint64_t wtmp_start = UINT64_MAX;
static int after_reboot = 0;

/* options for last */
static int hostlast = 0;
static int nohostname = 0;
static int noservice = 1;
static const int name_len = 8; /* LAST_LOGIN_LEN */
static int login_fmt = TIMEFMT_SHORT;
static int login_len = 16; /* 16 = short, 24 = full */
static int logout_fmt = TIMEFMT_HHMM;
static int logout_len = 5; /* 5 = short, 24 = full */
static const int host_len = 16; /* LAST_DOMAIN_LEN */
static unsigned int maxentries = 0; /* max number of entries to show */
static unsigned int currentry = 0; /* number of entries already printed */
static time_t present = 0; /* Who was present at the specified time */
static time_t since = 0; /* Who was logged in after this time? */
static time_t until = 0; /* Who was logged in until this time? */

static int
parse_time (const char *str, time_t *time)
{
  struct tm res;

  char *r = strptime (str, "%Y-%m-%d %T",  &res);

  if (r == NULL || *r != '\0')
    return -1;

  *time = mktime (&res);

  return 0;
}

static void
format_time (int fmt, char *dst, size_t dstlen, time_t t)
{
  switch (fmt)
    {
    case TIMEFMT_CTIME:
      snprintf (dst, dstlen, "%s", ctime (&t));
      dst[strlen (dst)-1] = '\0'; /* Remove trailing '\n' */
      break;
    case TIMEFMT_SHORT:
      {
	struct tm *tm = localtime (&t);
	strftime (dst, dstlen, "%a %b %e %H:%M", tm);
	break;
      }
    case TIMEFMT_HHMM:
      {
	struct tm *tm = localtime (&t);
	strftime (dst, dstlen, "%H:%M", tm);
	break;
      }
    default:
      abort ();
    }
}

static int
print_entry (void *unused __attribute__((__unused__)),
	     int argc, char **argv, char **azColName)
{
  char logintime[32]; /* LAST_TIMESTAMP_LEN */
  char logouttime[32]; /* LAST_TIMESTAMP_LEN */
  char length[32]; /* LAST_TIMESTAMP_LEN */
  char *line;
  char *endptr;

  /* Yes, it's waste of time to let sqlite iterate through all entries
     even if we don't need more anymore, but telling sqlite we don't
     want more leads to a "query aborted" error... */
  if (maxentries && currentry >= maxentries)
    return 0;

  /* ID, Type, User, LoginTime, LogoutTime, TTY, RemoteHost, Service */
  if (argc != 8)
    {
      fprintf (stderr, "Mangled entry:");
      for (int i = 0; i < argc; i++)
        fprintf (stderr, " %s=%s", azColName[i], argv[i] ? argv[i] : "NULL");
      fprintf (stderr, "\n");
      exit (EXIT_FAILURE);
    }

  const int type = atoi (argv[1]);
  const char *user = argv[2];
  const char *tty = argv[5]?argv[5]:"?";
  const char *host = argv[6]?argv[6]:"";
  const char *service = argv[7]?argv[7]:"";

  uint64_t login_t = strtoul(argv[3], &endptr, 10);
  if ((errno == ERANGE && login_t == UINT64_MAX)
      || (endptr == argv[3]) || (*endptr != '\0'))
    fprintf (stderr, "Invalid numeric time entry for 'login': '%s'\n",
	     argv[3]);

  if (login_t < wtmp_start)
    wtmp_start = login_t;

  if (since && (since > (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  if (until && (until < (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  if (present && (present < (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  format_time (login_fmt, logintime, sizeof (logintime),
	       login_t/USEC_PER_SEC);

  if (argv[4])
    {
      int64_t logout_t = strtoul(argv[4], &endptr, 10);
      if ((errno == ERANGE && logout_t == INT64_MAX)
	  || (endptr == argv[3]) || (*endptr != '\0'))
	fprintf (stderr, "Invalid numeric time entry for 'logout': '%s'\n",
		 argv[4]);

      if (present && (0 < (logout_t/USEC_PER_SEC)) &&
	  ((time_t)(logout_t/USEC_PER_SEC) < present))
	return 0;

      format_time (logout_fmt, logouttime, sizeof (logouttime),
		   logout_t/USEC_PER_SEC);

      int64_t secs = (logout_t - login_t)/USEC_PER_SEC;
      int mins  = (secs / 60) % 60;
      int hours = (secs / 3600) % 24;
      int days  = secs / 86400;

      if (days)
	snprintf (length, sizeof(length), "(%d+%02d:%02d)", days, hours, mins);
      else if (hours)
	snprintf (length, sizeof(length), " (%02d:%02d)", hours, mins);
      else
	snprintf (length, sizeof(length), " (00:%02d)", mins);
    }
  else /* login but no logout */
    {
      if (after_reboot)
	{
	  snprintf (logouttime, sizeof (logouttime), "crash");
	  length[0] = '\0';
	}
      else
	{
	  switch (type)
	    {
	    case USER_PROCESS:
	      if (logout_fmt == TIMEFMT_HHMM)
		{
		  snprintf (logouttime, sizeof (logouttime), "still");
		  snprintf(length, sizeof(length), "logged in");
		}
	      else
		{
		  snprintf (logouttime, sizeof (logouttime), "still logged in");
		  length[0] = '\0';
		}
	      break;
	    case BOOT_TIME:
	      if (logout_fmt == TIMEFMT_HHMM)
		{
		  snprintf (logouttime, sizeof (logouttime), "still");
		  snprintf(length, sizeof(length), "running");
		}
	      else
		{
		  snprintf (logouttime, sizeof (logouttime), "still running");
		  length[0] = '\0';
		}
	      break;
	    default:
	      snprintf (logouttime, sizeof (logouttime), "ERROR");
	      snprintf(length, sizeof(length), "Unknown: %d", type);
	      break;
	    }
	}
    }

  if (type == BOOT_TIME)
    {
      tty = "system boot";
      after_reboot = 1;
    }

  char *print_service = NULL;
  if (noservice)
    print_service = strdup ("");
  else
    {
      if (asprintf (&print_service, " %-12.12s", service) < 0)
	{
	  fprintf (stderr, "Out f memory");
	  exit (EXIT_FAILURE);
	}
    }

  if (nohostname)
    {
      if (asprintf (&line, "%-8.*s %-12.12s%s %-*.*s - %-*.*s %s\n",
		    name_len, user, tty, print_service,
		    login_len, login_len, logintime,
		    logout_len, logout_len, logouttime,
		    length) < 0)
	{
	  fprintf (stderr, "Out f memory");
	  exit (EXIT_FAILURE);
	}
    }
  else
    {
      if (hostlast)
	{
	  if (asprintf (&line, "%-8.*s %-12.12s%s %-*.*s - %-*.*s %-12.12s %s\n",
			name_len, user, tty, print_service,
			login_len, login_len, logintime,
			logout_len, logout_len, logouttime,
			length, host) < 0)
	    {
	      fprintf (stderr, "Out f memory");
	      exit (EXIT_FAILURE);
	    }
	}
      else
	{
	  if (asprintf (&line, "%-8.*s %-12.12s %-16.*s%s %-*.*s - %-*.*s %s\n",
			name_len, user, tty,
			host_len, host, print_service,
			login_len, login_len, logintime,
			logout_len, logout_len, logouttime,
			length) < 0)
	    {
	      fprintf (stderr, "Out f memory");
	      exit (EXIT_FAILURE);
	    }
	}
    }
  free (print_service);

  printf ("%s", line);
  free (line);

  currentry++;

  return 0;
}

static void
usage (int retval)
{
  FILE *output = (retval != EXIT_SUCCESS) ? stderr : stdout;

  fprintf (output, "Usage: wtmpdb [command] [options]\n");
  fputs ("Commands: last, boot, rotate, shutdown\n\n", output);
  fputs ("Options for last:\n", output);
  fputs ("  -a, --lasthost      Display hostnames as last entry\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("  -F, --fulltimes     Display full times and dates\n", output);
  fputs ("  -n, --limit N       Display only first N entries\n", output);
  fputs ("  -p, --present TIME  Display who was present at TIME\n", output);
  fputs ("  -R, --nohostname    Don't display hostname\n", output);
  fputs ("  -S, --service       Display PAM service used to login\n", output);
  fputs ("  -s, --since TIME    Display who was logged in after TIME\n", output);
  fputs ("  -t, --until TIME    Display who was logged in until TIME\n", output);
  fputs ("TIME must be in the format \"YYYY-MM-DD HH:MM:SS\"\n", output);
  fputs ("\n", output);

  fputs ("Options for boot (writes boot entry to wtmpdb):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("\n", output);

  fputs ("Options for rotate (exports old entries to wtmpdb_<datetime>)):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("  -d, --days INTEGER  Export all entries which are older than the given days\n", output);
  fputs ("\n", output);

  fputs ("Options for shutdown (writes shutdown time to wtmpdb):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("\n", output);

  fputs ("Generic options:\n", output);
  fputs ("  -h, --help          Display this help message and exit\n", output);
  fputs ("  -v, --version       Print version number and exit\n", output);
  fputs ("\n", output);
  exit (retval);
}

static int
main_logrotate (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {"days", no_argument, NULL, 'd'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int days = LOGROTATE_DAYS;

  int c;

  while ((c = getopt_long (argc, argv, "f:d:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
	case 'd':
	  days = atoi (optarg);
	  break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  if (wtmpdb_logrotate (wtmpdb_path, days, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't read all wtmp entries\n");

      exit (EXIT_FAILURE);
    }

  char wtmptime[32];
  format_time (TIMEFMT_CTIME, wtmptime, sizeof (wtmptime),
	       wtmp_start/USEC_PER_SEC);
  printf ("\n%s begins %s\n", wtmpdb_path, wtmptime);

  return EXIT_SUCCESS;
}

static int
main_last (int argc, char **argv)
{
  struct option const longopts[] = {
    {"hostlast", no_argument, NULL, 'a'},
    {"file", required_argument, NULL, 'f'},
    {"fulltimes", no_argument, NULL, 'F'},
    {"limit", required_argument, NULL, 'n'},
    {"present", required_argument, NULL, 'p'},
    {"nohostname", no_argument, NULL, 'R'},
    {"since", required_argument, NULL, 's'},
    {"service", no_argument, NULL, 'S'},
    {"until", required_argument, NULL, 'u'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "af:Fn:p:RSs:t:", longopts, NULL)) != -1)
    {
      switch (c)
        {
	case 'a':
	  hostlast = 1;
	  break;
        case 'f':
          wtmpdb_path = optarg;
          break;
	case 'F':
	  login_fmt = TIMEFMT_CTIME;
	  login_len = 24;
	  logout_fmt = TIMEFMT_CTIME;
	  logout_len = 24;
	  break;
	case 'n':
	  maxentries = atoi (optarg);
	  break;
	case 'p':
	  if (parse_time (optarg, &present) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 'R':
	  nohostname = 1;
	  break;
	case 's':
	  if (parse_time (optarg, &since) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 'S':
	  noservice = 0;
	  break;
	case 'u':
	  if (parse_time (optarg, &until) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  if (nohostname && hostlast)
    {
      fprintf (stderr, "The options -a and -R cannot be used together.\n");
      usage (EXIT_FAILURE);
    }

  if (wtmpdb_read_all (wtmpdb_path, print_entry, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't read all wtmp entries\n");

      exit (EXIT_FAILURE);
    }

  char wtmptime[32];
  format_time (TIMEFMT_CTIME, wtmptime, sizeof (wtmptime),
	       wtmp_start/USEC_PER_SEC);
  printf ("\n%s begins %s\n", wtmpdb_path, wtmptime);

  return EXIT_SUCCESS;
}

#if HAVE_AUDIT
static void
log_audit (int type)
{
  int audit_fd = audit_open();

  if (audit_fd < 0)
    {
      fprintf (stderr, "Failed to connect to audit daemon: %s\n",
	       strerror (errno));
      return;
    }

  if (audit_log_user_comm_message(audit_fd, type, "", "wtmpdb", NULL, NULL, NULL, 1) < 0)
    fprintf (stderr, "Failed to send audit message: %s",
	     strerror (errno));
  audit_close (audit_fd);
}
#endif

static struct timespec
diff_timespec(const struct timespec *time1, const struct timespec *time0)
{
  struct timespec diff = {.tv_sec = time1->tv_sec - time0->tv_sec,
    .tv_nsec = time1->tv_nsec - time0->tv_nsec};
  if (diff.tv_nsec < 0) {
    diff.tv_nsec += 1000000000; // nsec/sec
    diff.tv_sec--;
  }
  return diff;
}

static int
main_boot (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "f:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  struct utsname uts;
  uname(&uts);

  struct timespec ts_now;
  struct timespec ts_boot;
  clock_gettime (CLOCK_REALTIME, &ts_now);
  clock_gettime (CLOCK_BOOTTIME, &ts_boot);
  int64_t time = wtmpdb_timespec2usec (diff_timespec(&ts_now, &ts_boot));

#if HAVE_AUDIT
  log_audit (AUDIT_SYSTEM_BOOT);
#endif

  if (wtmpdb_login (wtmpdb_path, BOOT_TIME, "reboot", time, "~", uts.release,
		    NULL, &error) < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't write boot entry\n");

      exit (EXIT_FAILURE);
    }

  return EXIT_SUCCESS;
}

static int
main_shutdown (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "f:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

#if HAVE_AUDIT
  log_audit (AUDIT_SYSTEM_SHUTDOWN);
#endif

  int64_t id = wtmpdb_get_id (wtmpdb_path, "~", &error);
  if (id < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't get ID for reboot entry\n");

      exit (EXIT_FAILURE);
    }

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  int64_t time = wtmpdb_timespec2usec (ts);

  if (wtmpdb_logout (wtmpdb_path, id, time, &error) < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't write shutdown entry\n");

      exit (EXIT_FAILURE);
    }

  return EXIT_SUCCESS;
}

int
main (int argc, char **argv)
{
  struct option const longopts[] = {
    {"help",     no_argument,       NULL, 'h'},
    {"version",  no_argument,       NULL, 'v'},
    {NULL, 0, NULL, '\0'}
  };
  int c;

  if (strcmp (basename(argv[0]), "last") == 0)
    return main_last (argc, argv);
  else if (argc == 1)
    usage (EXIT_SUCCESS);
  else if (strcmp (argv[1], "last") == 0)
    return main_last (--argc, ++argv);
  else if (strcmp (argv[1], "boot") == 0)
    return main_boot (--argc, ++argv);
  else if (strcmp (argv[1], "shutdown") == 0)
    return main_shutdown (--argc, ++argv);
  else if (strcmp (argv[1], "rotate") == 0)
    return main_logrotate (--argc, ++argv);

  while ((c = getopt_long (argc, argv, "hv", longopts, NULL)) != -1)
    {
      switch (c)
	{
	case 'h':
	  usage (EXIT_SUCCESS);
	  break;
	case 'v':
	  printf ("wtmpdb %s\n", PROJECT_VERSION);
	  break;
	default:
	  usage (EXIT_FAILURE);
	  break;
	}
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  exit (EXIT_SUCCESS);
}
