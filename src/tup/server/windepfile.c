/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2010  James McKaskill
 * Copyright (C) 2010-2012  Mike Shal <marfey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "tup/server.h"
#include "tup/mapping.h"
#include "tup/config.h"
#include "tup/flist.h"
#include "tup/environ.h"
#include "tup/mapping.h"
#include "dllinject/dllinject.h"
#include "compat/win32/dirpath.h"
#include "compat/win32/open_notify.h"
#include "compat/dir_mutex.h"
#include <stdio.h>
#include <errno.h>

#define TUP_TMP ".tup/tmp"

static int initialize_depfile(struct server *s, char *depfile);
static int process_depfile(struct server *s, const char *depfile);
static int server_inited = 0;
static BOOL WINAPI console_handler(DWORD cevent);
static sig_atomic_t event_got = -1;

static char tuptmpdir[PATH_MAX];

int server_pre_init(void)
{
	return 0;
}

int server_post_exit(void)
{
	return 0;
}

int server_init(enum server_mode mode)
{
	char *slash;
	char tupexecdir[PATH_MAX];
	char cwd[PATH_MAX];
	char tmpdir[PATH_MAX];
	struct flist f = {0, 0, 0};
	int cwdlen;

	if(mode) {/* unused */}

	if(server_inited)
		return 0;

	if (GetModuleFileNameA(NULL, tupexecdir, PATH_MAX - 1) == 0)
		return -1;

	tupexecdir[PATH_MAX - 1] = '\0';
	slash = strrchr(tupexecdir, '\\');
	if (slash) {
		*slash = '\0';
	}

	if(fchdir(tup_top_fd()) < 0) {
		perror("fchdir");
		return -1;
	}

	if(getcwd(tuptmpdir, sizeof(tuptmpdir)) == NULL) {
		perror("getcwd");
		return -1;
	}
	cwdlen = strlen(tuptmpdir);
	/* 64 is generous room for the "\deps-%i" for depfiles */
	if(cwdlen + 1 + sizeof(TUP_TMP) + 64 >= sizeof(tuptmpdir)) {
		fprintf(stderr, "tup error: tuptmpdir[] is sized incorrectly for .tup/tmp\n");
		return -1;
	}
	tuptmpdir[cwdlen] = '\\';
	memcpy(tuptmpdir + cwdlen + 1, ".tup\\tmp", sizeof(TUP_TMP));
	if(mkdir(TUP_TMP) < 0) {
		if(errno != EEXIST) {
			perror(TUP_TMP);
			fprintf(stderr, "tup error: Unable to create temporary working directory.\n");
			return -1;
		}
	}

	/* Go into the tmp directory and remove any files that may have been
	 * left over from a previous tup invocation.
	 */
	if(chdir(TUP_TMP) < 0) {
		perror(TUP_TMP);
		fprintf(stderr, "tup error: Unable to chdir to the tmp directory.\n");
		return -1;
	}
	flist_foreach(&f, ".") {
		if(f.filename[0] != '.') {
			if(unlink(f.filename) != 0) {
				perror(f.filename);
				fprintf(stderr, "tup error: Unable to clean out a file in .tup/tmp directory. Please try cleaning this directory manually. Note there may be a stuck sub-process that still has the file open (check the Task Manager).\n");
				return -1;
			}
		}
	}
	if(fchdir(tup_top_fd()) < 0) {
		perror("fchdir");
		return -1;
	}

	if(SetConsoleCtrlHandler(console_handler, TRUE) == 0) {
		perror("SetConsoleCtrlHandler");
		fprintf(stderr, "tup error: Unable to set the CTRL-C handler.\n");
		return -1;
	}

	snprintf(tmpdir, sizeof(tmpdir), "%s\\.tup\\tmp", getcwd(cwd, sizeof(cwd)));
	tup_inject_setexecdir(tupexecdir, tmpdir);
	server_inited = 1;

	return 0;
}

int server_quit(void)
{
	return 0;
}

/* This runs with the dir_mutex taken. We need to make sure that we:
 * 1) Create the output file with the inherit flag set
 * 2) We start the new process to inherit that file
 * 3) We close down the file so that no other process inherits it (ie: if we
 *    are running in parallel - we don't want anyone else to get our output file
 *    handle)
 */
static int create_process(struct server *s, int dfd, char *cmdline,
			  struct tup_env *newenv,
			  PROCESS_INFORMATION *pi)
{
	STARTUPINFOA sa;
	SECURITY_ATTRIBUTES sec;
	BOOL ret;
	char buf[64];

	memset(&sa, 0, sizeof(sa));
	sa.cb = sizeof(STARTUPINFOW);

	memset(&sec, 0, sizeof(sec));
	sec.nLength = sizeof(sec);
	sec.lpSecurityDescriptor = NULL;
	sec.bInheritHandle = TRUE;

	if(chdir(win32_get_dirpath(tup_top_fd())) < 0) {
		perror("chdir");
		fprintf(stderr, "tup error: Unable to chdir to the project root directory to create a temporary output file.\n");
		return -1;
	}
	snprintf(buf, sizeof(buf), ".tup\\tmp\\output-%i", s->id);
	buf[sizeof(buf)-1] = 0;
	sa.hStdOutput = CreateFile(buf, GENERIC_WRITE, 0, &sec, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if(sa.hStdOutput == INVALID_HANDLE_VALUE) {
		perror(buf);
		fprintf(stderr, "tup error: Unable to create temporary file for stdout\n");
		return -1;
	}
	sa.hStdError = sa.hStdOutput;
	sa.dwFlags = STARTF_USESTDHANDLES;

	pi->hProcess = INVALID_HANDLE_VALUE;
	pi->hThread = INVALID_HANDLE_VALUE;

	/* Passing in the directory to lpCurrentDirectory is insufficient
	 * because the command may run as './foo.exe', so we need to change to
	 * the correct directory before calling CreateProcessA. This may just
	 * happen to work in most cases because the unlinkat() called to remove
	 * the outputs will usually change to the correct directory anyway.
	 * This isn't necessarily the case if the command has no outputs, and
	 * also wouldn't be synchronized.
	 */
	if(chdir(win32_get_dirpath(dfd))) {
		fprintf(stderr, "tup error: Unable to change working directory to '%s'\n", win32_get_dirpath(dfd));
		return -1;
	}
	ret = CreateProcessA(
		NULL,
		cmdline,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		newenv->envblock,
		NULL,
		&sa,
		pi);
	CloseHandle(sa.hStdOutput);

	if(!ret)
		return -1;
	return 0;
}

#define SHSTR  "sh -c '"
#define CMDSTR "CMD.EXE /Q /C "
int server_exec(struct server *s, int dfd, const char *cmd, struct tup_env *newenv,
		struct tup_entry *dtent, int full_deps)
{
	int rc = -1;
	DWORD return_code = 1;
	PROCESS_INFORMATION pi;
	size_t namesz = strlen(cmd);
	size_t cmdsz = sizeof(CMDSTR) - 1;
	char* cmdline = (char*) __builtin_alloca(namesz + cmdsz + 1 + 1);
	char buf[64];
	char depfile[PATH_MAX];

	int have_shell = strncmp(cmd, "sh ", 3) == 0
		|| strncmp(cmd, "bash ", 5) == 0
		|| strncmp(cmd, "cmd ", 4) == 0;

	int need_sh = 0;

	int need_cmd = 0;

	if(dtent) {}
	if(full_deps) {}

	if(initialize_depfile(s, depfile) < 0) {
		fprintf(stderr, "Error starting update server.\n");
		return -1;
	}

	cmdline[0] = '\0';
	/* Only pull in cmd/sh if really necessary */
	if(!have_shell) {
		need_sh = strncmp(cmd, "./", 2) == 0 ||
			strchr(cmd, '`') != NULL;
		need_cmd = strchr(cmd, '&') != NULL ||
			strchr(cmd, '|') != NULL ||
			strchr(cmd, '>') != NULL ||
			strchr(cmd, '<') != NULL;
		if(need_sh) {
			strcat(cmdline, SHSTR);
		} else if(need_cmd) {
			strcat(cmdline, CMDSTR);
		}
	}
	strcat(cmdline, cmd);
	if(need_sh) {
		strcat(cmdline, "'");
	}

	pthread_mutex_lock(&dir_mutex);
	if(create_process(s, dfd, cmdline, newenv, &pi) < 0) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to create child process: %s\n", strerror(errno));
		if(errno == ERANGE) {
			fprintf(stderr, "tup error: This error may mean that Windows could not find the program in the PATH.\n");
		}
		pthread_mutex_unlock(s->error_mutex);

		pthread_mutex_unlock(&dir_mutex);
		goto end;
	}
	pthread_mutex_unlock(&dir_mutex);

	if(tup_inject_dll(&pi, depfile, s->id)) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to inject dll: %s\n", strerror(errno));
		pthread_mutex_unlock(s->error_mutex);
		goto err_terminate;
	}

	if(ResumeThread(pi.hThread) == (DWORD)~0) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to start thread: %s\n", strerror(errno));
		pthread_mutex_unlock(s->error_mutex);
		goto err_terminate;
	}

	if(WaitForSingleObject(pi.hThread, INFINITE) != WAIT_OBJECT_0) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to wait for thread: %s\n", strerror(errno));
		pthread_mutex_unlock(s->error_mutex);
		goto err_terminate;
	}

	if(WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to wait for process: %s\n", strerror(errno));
		pthread_mutex_unlock(s->error_mutex);
		goto err_terminate;
	}

	if(!GetExitCodeProcess(pi.hProcess, &return_code)) {
		pthread_mutex_lock(s->error_mutex);
		fprintf(stderr, "tup error: failed to get exit code: %s\n", strerror(errno));
		pthread_mutex_unlock(s->error_mutex);
		goto err_terminate;
	}

	snprintf(buf, sizeof(buf), ".tup/tmp/output-%i", s->id);
	buf[sizeof(buf)-1] = 0;
	s->output_fd = openat(tup_top_fd(), buf, O_RDONLY);
	if(s->output_fd < 0) {
		pthread_mutex_lock(s->error_mutex);
		perror(buf);
		fprintf(stderr, "tup error: Unable to open sub-process output file after the process completed.\n");
		pthread_mutex_unlock(s->error_mutex);
		goto end;
	}

	s->exited = 1;
	s->exit_status = return_code;
	rc = 0;

end:
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if(process_depfile(s, depfile) < 0) {
		return -1;
	}
	if(unlink(depfile) < 0) {
		perror(depfile);
		fprintf(stderr, "tup error: Unable to unlink depfile\n");
	}
	return rc;

err_terminate:
	TerminateProcess(pi.hProcess, 10);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return -1;
}

int server_postexec(struct server *s)
{
	char buf[64];
	snprintf(buf, sizeof(buf), ".tup/tmp/output-%i", s->id);
	buf[sizeof(buf)-1] = 0;
	if(unlinkat(tup_top_fd(), buf, 0) < 0) {
		pthread_mutex_lock(s->error_mutex);
		perror(buf);
		fprintf(stderr, "tup error: Unable to unlink sub-process output file.\n");
		pthread_mutex_unlock(s->error_mutex);
		return -1;
	}
	return 0;
}

int server_is_dead(void)
{
	return (event_got != -1);
}

int server_config_start(struct server *s)
{
	/* Currently unused - this is only needed for symlink detection in fuse. */
	if(s) {}
	return 0;
}

int server_config_stop(struct server *s)
{
	if(s) {}
	return 0;
}

int server_parser_start(struct parser_server *ps)
{
	ps->root_fd = tup_top_fd();
	if(open_notify_push(&ps->s.finfo) < 0)
		return -1;
	return 0;
}

int server_parser_stop(struct parser_server *ps)
{
	if(open_notify_pop(&ps->s.finfo) < 0)
		return -1;
	return 0;
}

int server_run_script(tupid_t tupid, const char *cmdline,
		      struct tupid_entries *env_root, char **rules)
{
	if(tupid || cmdline || env_root || rules) {/* unsupported */}
	fprintf(stderr, "tup error: Run scripts are not yet supported on this platform.\n");
	return -1;
}

static int initialize_depfile(struct server *s, char *depfile)
{
	HANDLE h;

	snprintf(depfile, PATH_MAX, "%s\\deps-%i", tuptmpdir, s->id);
	depfile[PATH_MAX-1] = 0;

	h = CreateFile(depfile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(!h) {
		perror(depfile);
		fprintf(stderr, "tup error: Unable to create temporary file for dependency storage\n");
		return -1;
	}
	/* We just want the file to be created here since it's easier to display the error. The
	 * file is re-opened in the dllinject code in append mode.
	 */
	CloseHandle(h);
	return 0;
}

static int process_depfile(struct server *s, const char *depfile)
{
	char event1[PATH_MAX];
	char event2[PATH_MAX];
	FILE *f;

	f = fopen(depfile, "rb");
	if(!f) {
		perror(depfile);
		fprintf(stderr, "tup error: Unable to open dependency file for post-processing.\n");
		return -1;
	}
	while(1) {
		struct access_event event;

		if(fread(&event, sizeof(event), 1, f) != 1) {
			if(!feof(f)) {
				perror("fread");
				fprintf(stderr, "tup error: Unable to read the access_event structure from the dependency file.\n");
				return -1;
			}
			break;
		}

		if(!event.len)
			continue;

		if(event.len >= PATH_MAX - 1) {
			fprintf(stderr, "tup error: Size of %i bytes is longer than the max filesize\n", event.len);
			return -1;
		}
		if(event.len2 >= PATH_MAX - 1) {
			fprintf(stderr, "tup error: Size of %i bytes is longer than the max filesize\n", event.len2);
			return -1;
		}

		if(fread(&event1, event.len + 1, 1, f) != 1) {
			perror("fread");
			fprintf(stderr, "tup error: Unable to read the first event from the dependency file.\n");
			return -1;
		}
		if(fread(&event2, event.len2 + 1, 1, f) != 1) {
			perror("fread");
			fprintf(stderr, "tup error: Unable to read the second event from the dependency file.\n");
			return -1;
		}

		if(event1[event.len] != '\0' || event2[event.len2] != '\0') {
			fprintf(stderr, "tup error: Missing null terminator in access_event\n");
			return -1;
		}

		/* We duplicate writes here because the mapping tree in
		 * dllinject is needed in the process space to handle mappings,
		 * and also for us because we need to move them over at the end.
		 * Contrast with the fuse server which already has the mappings
		 * locally.
		 */
		if(event.at == ACCESS_WRITE) {
			printf("Got write event[%i, %i]: '%s', '%s'\n", event.len, event.len2, event1, event2);
			if(!add_mapping(event1, event2, &s->finfo.mapping_root)) {
				fprintf(stderr, "tup error: Unable to insert mapping for file '%s'\n", event1);
				return -1;
			}
		} else if(event.at == ACCESS_UNLINK) {
			struct mapping *map;
			char *filename;
			map = get_mapping(event1, &s->finfo.mapping_root);
			if(!map) {
				fprintf(stderr, "tup error: Got an ACCESS_UNLINK event without a corresponding file mapping for file '%s'\n", event1);
				return -1;
			}
			filename = map->tmpname;
			filename = strstr(map->tmpname, ".tup\\tmp");
			if(!filename) {
				fprintf(stderr, "tup error: Expected to find '.tup\\tmp' in the temporary filename for file: %s\n", map->tmpname);
				return -1;
			}
			if(unlink(filename) < 0) {
				perror(filename);
				fprintf(stderr, "tup error: Unable to unlink temporary output file.\n");
				return -1;
			}
			printf("UNLINK: %s\n", map->tmpname);
			del_mapping(map, &s->finfo.mapping_root);
		} else {
			if(handle_file(event.at, event1, &s->finfo) < 0) {
				fprintf(stderr, "Error: Failed to call handle_file on event '%s'\n", event1);
				return -1;
			}
		}
	}
	if(fclose(f) < 0) {
		perror("fclose");
		return -1;
	}
	return 0;
}

static BOOL WINAPI console_handler(DWORD cevent)
{
	event_got = cevent;
	return TRUE;
}
