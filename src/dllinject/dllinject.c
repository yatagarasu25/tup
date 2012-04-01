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

#define BUILDING_DLLINJECT
#include "dllinject.h"
#include "win_handle_map.h"
#include "tup/access_event.h"
#include "tup/mapping.h"

#include <windows.h>
#include <ntdef.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <ctype.h>
#include <shlwapi.h>
#include <ddk/ntapi.h>

#ifndef __in
#define __in
#define __out
#define __inout
#define __in_opt
#define __inout_opt
#define __reserved
#endif

#ifndef NDEBUG
#	define DEBUG_HOOK debug_hook

static const char* access_type_name[] = {
	"read",
	"write",
	"unlink",
	"var",
};

FILE *debugf = NULL;
int opening = 0;
static void debug_hook(const char* format, ...)
{
	DWORD save_error = GetLastError();

	char buf[256];
	va_list ap;
	if(debugf == NULL && !opening) {
		opening = 1;
		debugf = fopen("c:\\cygwin\\home\\marf\\ok.txt", "a");
		fflush(stdout);
	}
	if(debugf == NULL) {
		printf("No file :(\n");
		goto exit;
	}
	va_start(ap, format);
	vsnprintf(buf, 255, format, ap);
	buf[255] = '\0';
	fprintf(debugf, buf);
	fflush(debugf);

exit:;
	SetLastError( save_error );
}
#else
#	define DEBUG_HOOK(...)
#endif

typedef HFILE (WINAPI *OpenFile_t)(
    __in    LPCSTR lpFileName,
    __inout LPOFSTRUCT lpReOpenBuff,
    __in    UINT uStyle);

#if 0
typedef HANDLE (WINAPI *CreateFileA_t)(
    __in     LPCSTR lpFileName,
    __in     DWORD dwDesiredAccess,
    __in     DWORD dwShareMode,
    __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in     DWORD dwCreationDisposition,
    __in     DWORD dwFlagsAndAttributes,
    __in_opt HANDLE hTemplateFile);

typedef HANDLE (WINAPI *CreateFileW_t)(
    __in     LPCWSTR lpFileName,
    __in     DWORD dwDesiredAccess,
    __in     DWORD dwShareMode,
    __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in     DWORD dwCreationDisposition,
    __in     DWORD dwFlagsAndAttributes,
    __in_opt HANDLE hTemplateFile);

typedef HANDLE (WINAPI *CreateFileTransactedA_t)(
    __in       LPCSTR lpFileName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwShareMode,
    __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in       DWORD dwCreationDisposition,
    __in       DWORD dwFlagsAndAttributes,
    __in_opt   HANDLE hTemplateFile,
    __in       HANDLE hTransaction,
    __in_opt   PUSHORT pusMiniVersion,
    __reserved PVOID  lpExtendedParameter);

typedef HANDLE (WINAPI *CreateFileTransactedW_t)(
    __in       LPCWSTR lpFileName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwShareMode,
    __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in       DWORD dwCreationDisposition,
    __in       DWORD dwFlagsAndAttributes,
    __in_opt   HANDLE hTemplateFile,
    __in       HANDLE hTransaction,
    __in_opt   PUSHORT pusMiniVersion,
    __reserved PVOID  lpExtendedParameter);
#endif

typedef BOOL (WINAPI *DeleteFileA_t)(
    __in LPCSTR lpFileName);

typedef BOOL (WINAPI *DeleteFileW_t)(
    __in LPCWSTR lpFileName);

typedef BOOL (WINAPI *DeleteFileTransactedA_t)(
    __in     LPCSTR lpFileName,
    __in     HANDLE hTransaction);

typedef BOOL (WINAPI *DeleteFileTransactedW_t)(
    __in     LPCWSTR lpFileName,
    __in     HANDLE hTransaction);

typedef BOOL (WINAPI *MoveFileA_t)(
    __in LPCSTR lpExistingFileName,
    __in LPCSTR lpNewFileName);

typedef BOOL (WINAPI *MoveFileW_t)(
    __in LPCWSTR lpExistingFileName,
    __in LPCWSTR lpNewFileName);

typedef BOOL (WINAPI *MoveFileExA_t)(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in     DWORD    dwFlags);

typedef BOOL (WINAPI *MoveFileExW_t)(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in     DWORD    dwFlags);

typedef BOOL (WINAPI *MoveFileWithProgressA_t)(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags);

typedef BOOL (WINAPI *MoveFileWithProgressW_t)(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags);

typedef BOOL (WINAPI *MoveFileTransactedA_t)(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags,
    __in     HANDLE hTransaction);

typedef BOOL (WINAPI *MoveFileTransactedW_t)(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags,
    __in     HANDLE hTransaction);

typedef BOOL (WINAPI *ReplaceFileA_t)(
    __in       LPCSTR  lpReplacedFileName,
    __in       LPCSTR  lpReplacementFileName,
    __in_opt   LPCSTR  lpBackupFileName,
    __in       DWORD   dwReplaceFlags,
    __reserved LPVOID  lpExclude,
    __reserved LPVOID  lpReserved);

typedef BOOL (WINAPI *ReplaceFileW_t)(
    __in       LPCWSTR lpReplacedFileName,
    __in       LPCWSTR lpReplacementFileName,
    __in_opt   LPCWSTR lpBackupFileName,
    __in       DWORD   dwReplaceFlags,
    __reserved LPVOID  lpExclude,
    __reserved LPVOID  lpReserved);

typedef BOOL (WINAPI *CopyFileA_t)(
    __in LPCSTR lpExistingFileName,
    __in LPCSTR lpNewFileName,
    __in BOOL bFailIfExists);

typedef BOOL (WINAPI *CopyFileW_t)(
    __in LPCWSTR lpExistingFileName,
    __in LPCWSTR lpNewFileName,
    __in BOOL bFailIfExists);

typedef BOOL (WINAPI *CopyFileExA_t)(
    __in     LPCSTR lpExistingFileName,
    __in     LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags);

typedef BOOL (WINAPI *CopyFileExW_t)(
    __in     LPCWSTR lpExistingFileName,
    __in     LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags);

typedef BOOL (WINAPI *CopyFileTransactedA_t)(
    __in     LPCSTR lpExistingFileName,
    __in     LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags,
    __in     HANDLE hTransaction);

typedef BOOL (WINAPI *CopyFileTransactedW_t)(
    __in     LPCWSTR lpExistingFileName,
    __in     LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags,
    __in     HANDLE hTransaction);

typedef DWORD (WINAPI *GetFileAttributesA_t)(
    __in LPCSTR lpFileName);

typedef DWORD (WINAPI *GetFileAttributesW_t)(
    __in LPCWSTR lpFileName);

typedef BOOL (WINAPI *GetFileAttributesExA_t)(
    __in  LPCSTR lpFileName,
    __in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    __out LPVOID lpFileInformation);

typedef BOOL (WINAPI *GetFileAttributesExW_t)(
    __in  LPCWSTR lpFileName,
    __in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    __out LPVOID lpFileInformation);

typedef __out HANDLE (WINAPI *FindFirstFileA_t)(
    __in  LPCSTR lpFileName,
    __out LPWIN32_FIND_DATAA lpFindFileData);

typedef __out HANDLE (WINAPI *FindFirstFileW_t)(
    __in  LPCWSTR lpFileName,
    __out LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL (WINAPI *FindNextFileA_t)(
    __in  HANDLE hFindFile,
    __out LPWIN32_FIND_DATAA lpFindFileData);

typedef BOOL (WINAPI *FindNextFileW_t)(
    __in  HANDLE hFindFile,
    __out LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL (WINAPI *CreateProcessA_t)(
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI * CreateProcessW_t)(
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *CreateProcessAsUserA_t)(
    __in_opt    HANDLE hToken,
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *CreateProcessAsUserW_t)(
    __in_opt    HANDLE hToken,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation
    );

typedef BOOL (WINAPI *CreateProcessWithLogonW_t)(
    __in        LPCWSTR lpUsername,
    __in_opt    LPCWSTR lpDomain,
    __in        LPCWSTR lpPassword,
    __in        DWORD dwLogonFlags,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *CreateProcessWithTokenW_t)(
    __in        HANDLE hToken,
    __in        DWORD dwLogonFlags,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef NTSTATUS (WINAPI *NtOpenFile_t)(
    __out  PHANDLE FileHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG ShareAccess,
    __in   ULONG OpenOptions);

typedef NTSTATUS (WINAPI *NtCreateFile_t)(
    __out     PHANDLE FileHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt  PLARGE_INTEGER AllocationSize,
    __in      ULONG FileAttributes,
    __in      ULONG ShareAccess,
    __in      ULONG CreateDisposition,
    __in      ULONG CreateOptions,
    __in      PVOID EaBuffer,
    __in      ULONG EaLength);

typedef NTSTATUS (WINAPI *NtQueryDirectoryFile_t)(
   __in      HANDLE FileHandle,
   __in_opt  HANDLE Event,
   __in_opt  PIO_APC_ROUTINE ApcRoutine,
   __in_opt  PVOID ApcContext,
   __out     PIO_STATUS_BLOCK IoStatusBlock,
   __out     PVOID FileInformation,
   __in      ULONG Length,
   __in      FILE_INFORMATION_CLASS FileInformationClass,
   __in      BOOLEAN ReturnSingleEntry,
   __in_opt  PUNICODE_STRING FileName,
   __in      BOOLEAN RestartScan);

typedef int (*access_t)(const char *pathname, int mode);
typedef FILE *(*fopen_t)(const char *path, const char *mode);
typedef int (*rename_t)(const char *oldpath, const char *newpath);
typedef int (*remove_t)(const char *pathname);

static OpenFile_t			OpenFile_orig;
#if 0
static CreateFileA_t			CreateFileA_orig;
static CreateFileW_t			CreateFileW_orig;
static CreateFileTransactedA_t		CreateFileTransactedA_orig;
static CreateFileTransactedW_t		CreateFileTransactedW_orig;
#endif
static DeleteFileA_t			DeleteFileA_orig;
static DeleteFileW_t			DeleteFileW_orig;
static DeleteFileTransactedA_t		DeleteFileTransactedA_orig;
static DeleteFileTransactedW_t		DeleteFileTransactedW_orig;
static MoveFileA_t			MoveFileA_orig;
static MoveFileW_t			MoveFileW_orig;
static MoveFileExA_t			MoveFileExA_orig;
static MoveFileExW_t			MoveFileExW_orig;
static MoveFileWithProgressA_t		MoveFileWithProgressA_orig;
static MoveFileWithProgressW_t		MoveFileWithProgressW_orig;
static MoveFileTransactedA_t		MoveFileTransactedA_orig;
static MoveFileTransactedW_t		MoveFileTransactedW_orig;
static ReplaceFileA_t			ReplaceFileA_orig;
static ReplaceFileW_t			ReplaceFileW_orig;
static CopyFileA_t			CopyFileA_orig;
static CopyFileW_t			CopyFileW_orig;
static CopyFileExA_t			CopyFileExA_orig;
static CopyFileExW_t			CopyFileExW_orig;
static CopyFileTransactedA_t		CopyFileTransactedA_orig;
static CopyFileTransactedW_t		CopyFileTransactedW_orig;
static GetFileAttributesA_t		GetFileAttributesA_orig;
static GetFileAttributesW_t		GetFileAttributesW_orig;
static GetFileAttributesExA_t		GetFileAttributesExA_orig;
static GetFileAttributesExW_t		GetFileAttributesExW_orig;
static FindFirstFileA_t			FindFirstFileA_orig;
static FindFirstFileW_t			FindFirstFileW_orig;
static FindNextFileA_t			FindNextFileA_orig;
static FindNextFileW_t			FindNextFileW_orig;
static CreateProcessA_t			CreateProcessA_orig;
static CreateProcessW_t			CreateProcessW_orig;
static CreateProcessAsUserA_t		CreateProcessAsUserA_orig;
static CreateProcessAsUserW_t		CreateProcessAsUserW_orig;
static CreateProcessWithLogonW_t	CreateProcessWithLogonW_orig;
static CreateProcessWithTokenW_t	CreateProcessWithTokenW_orig;
static NtCreateFile_t			NtCreateFile_orig;
static NtOpenFile_t			NtOpenFile_orig;
static NtQueryDirectoryFile_t		NtQueryDirectoryFile_orig;
static access_t				_access_orig;
static fopen_t				fopen_orig;
static rename_t				rename_orig;
static remove_t				remove_orig;

#define handle_file(a, b, c) mhandle_file(a, b, c, __LINE__)
static void mhandle_file(const char* file, const char* file2, enum access_type at, int line);
#define handle_file_w(a, b, c) mhandle_file_w(a, b, c, __LINE__)
static void mhandle_file_w(const wchar_t* file, const wchar_t* file2, enum access_type at, int line);

static const char *strcasestr(const char *arg1, const char *arg2);
static const wchar_t *wcscasestr(const wchar_t *arg1, const wchar_t *arg2);
static int pre_process_mappings(void);

static char s_depfilename[PATH_MAX];
static FILE *depf = NULL;

static int writef(const char *data, unsigned int len)
{
	int rc = 0;
/*	DWORD num_written;

	if(!WriteFile(deph, data, len, &num_written, NULL)) {
		DEBUG_HOOK("failed to write %i bytes\n", len);
		rc = -1;
	}
	if(num_written != len) {
		DEBUG_HOOK("failed to write exactly %i bytes\n", len);
		rc = -1;
	}*/
	pre_process_mappings();
	fwrite(data, len, 1, depf);
	fseek(depf, 0, SEEK_END);
	fflush(depf);
	return rc;
}

static int sid;
static struct string_entries mapping_root = RB_INITIALIZER(&mapping_root);

static char execdir[MAX_PATH];
static char tmpdir[MAX_PATH];

/* Bit 29 is the application error bit, and just set it with our line number. Add
 * in bit 28 for funsies in case the real application uses just bit 29.
 */
#define SET_ERROR() SetLastError(0x30000000 | __LINE__)

static int fileid = 0;

static int pre_process_mappings(void)
{
	char event1[PATH_MAX];
	char event2[PATH_MAX];

	while(1) {
		struct access_event event;
		if(fread(&event, sizeof(event), 1, depf) != 1) {
			if(!feof(depf)) {
				perror("fread");
				return -1;
			}
			break;
		}
		if(!event.len)
			continue;
		if(fread(&event1, event.len + 1, 1, depf) != 1) {
			perror("fread");
			return -1;
		}
		if(fread(&event2, event.len2 + 1, 1, depf) != 1) {
			perror("fread");
			return -1;
		}
		if(event.at == ACCESS_WRITE) {
			DEBUG_HOOK("New mapping (pre-process)[%i]: %s -> %s\n", GetCurrentProcessId(), event1, event2);
			if(!add_mapping(event1, event2, &mapping_root)) {
				fprintf(stderr, "Unable to add pre-map for %s\n", event1);
				return -1;
			}
			fileid++;
		}
	}
	return 0;
}

static struct mapping *mget_mapping(const char *path, struct string_entries *mroot)
{
	if(pre_process_mappings() < 0)
		return NULL;
	return get_mapping(path, mroot);
}

#define tup_get_write(a) __tup_get_write(a, __LINE__)
static LPCSTR __tup_get_write(__in LPCSTR filename, int line)
{
	struct mapping *map;

	if(strcmp(filename, "CONOUT$") == 0)
		return filename;

	DEBUG_HOOK("Get[%i] mapping (write)[%i]: %s\n", line, GetCurrentProcessId(), filename);
	map = mget_mapping(filename, &mapping_root);
	if(!map) {
		char tmpfilename[PATH_MAX];
		fileid++;
		snprintf(tmpfilename, sizeof(tmpfilename), "%s\\%i-%x", tmpdir, sid, fileid);
		DEBUG_HOOK("New mapping[%i]: %s -> %s\n", GetCurrentProcessId(), filename, tmpfilename);
		map = add_mapping(filename, tmpfilename, &mapping_root);
		handle_file(filename, tmpfilename, ACCESS_WRITE);
	}
	return map->tmpname;
}

static LPCSTR tup_get_write_w(__in LPCWSTR filename)
{
	char afile[PATH_MAX];
	size_t fsz = filename ? wcslen(filename) : 0;
	int count;
	count = WideCharToMultiByte(CP_UTF8, 0, filename, fsz, afile, PATH_MAX, NULL, NULL);
	afile[count] = 0;
	return tup_get_write(afile);
}

static LPCSTR tup_get_read_no_handle(__in LPCSTR filename)
{
	struct mapping *map;
	DEBUG_HOOK("Get mapping (read no h)[%i]: %s\n", GetCurrentProcessId(), filename);
	map = mget_mapping(filename, &mapping_root);
	if(map) {
		return map->tmpname;
	}
	return filename;
}

static LPCSTR tup_get_read_no_handle_w(__in LPCWSTR filename, char *outfile)
{
	size_t fsz = filename ? wcslen(filename) : 0;
	int count;
	count = WideCharToMultiByte(CP_UTF8, 0, filename, fsz, outfile, PATH_MAX, NULL, NULL);
	outfile[count] = 0;
	return tup_get_read_no_handle(outfile);
}

static LPCSTR tup_get_read(__in LPCSTR filename)
{
	struct mapping *map;
	DEBUG_HOOK("Get mapping (read)[%i]: %s\n", GetCurrentProcessId(), filename);
	map = mget_mapping(filename, &mapping_root);
	if(map) {
		/* If we have a mapping, that means we're writing to the file
		 * and don't need to call handle_file().
		 */
		return map->tmpname;
	}
	handle_file(filename, NULL, ACCESS_READ);
	return filename;
}

static LPCSTR tup_get_read_w(__in LPCWSTR filename, char *outfile)
{
	size_t fsz = filename ? wcslen(filename) : 0;
	int count;
	count = WideCharToMultiByte(CP_UTF8, 0, filename, fsz, outfile, PATH_MAX, NULL, NULL);
	outfile[count] = 0;
	return tup_get_read(outfile);
}

static BOOL tup_unlink(__in LPCSTR filename)
{
	struct mapping *map;
	DEBUG_HOOK("unlink: %s\n", filename);
	map = mget_mapping(filename, &mapping_root);
	if(map) {
		/* The file is cleaned up in the server when it sees the ACCESS_UNLINK path */
		del_mapping(map, &mapping_root);
		handle_file(filename, NULL, ACCESS_UNLINK);
		return TRUE;
	}
	SET_ERROR();
	return FALSE;
}

static BOOL tup_unlink_w(__in LPCWSTR filename)
{
	char afile[PATH_MAX];
	size_t fsz = wcslen(filename);
	int count;

	count = WideCharToMultiByte(CP_UTF8, 0, filename, fsz, afile, PATH_MAX, NULL, NULL);
	afile[count] = 0;
	DEBUG_HOOK("unlinkW: %s\n", afile);
	return tup_unlink(afile);
}

static BOOL tup_rename(__in LPCSTR lpExistingFileName, __in LPCSTR lpNewFileName)
{
	struct mapping *map;

	DEBUG_HOOK("Rename: '%s' -> '%s'\n", lpExistingFileName, lpNewFileName);
	/* See if we already have a file at the new destination. If so, remove
	 * it.
	 */
	map = mget_mapping(lpNewFileName, &mapping_root);
	if(map) {
		DeleteFileA_orig(map->tmpname);
		del_mapping(map, &mapping_root);
	}

	map = mget_mapping(lpExistingFileName, &mapping_root);
	if(!map) {
		SET_ERROR();
		return FALSE;
	}
	string_tree_rm(&mapping_root, &map->realname);
	free(map->realname.s);
	map->realname.s = strdup(lpNewFileName);
	if(!map->realname.s) {
		SET_ERROR();
		return FALSE;
	}
	map->realname.len = strlen(map->realname.s);
	if(string_tree_insert(&mapping_root, &map->realname) < 0) {
		SET_ERROR();
		return FALSE;
	}
	return TRUE;
}

static BOOL tup_rename_w(__in LPCWSTR lpExistingFileName, __in LPCWSTR lpNewFileName)
{
	char afile[PATH_MAX];
	char afile2[PATH_MAX];
	size_t fsz = wcslen(lpExistingFileName);
	size_t f2sz = wcslen(lpNewFileName);
	int count;

	count = WideCharToMultiByte(CP_UTF8, 0, lpExistingFileName, fsz, afile, PATH_MAX, NULL, NULL);
	afile[count] = 0;
	count = WideCharToMultiByte(CP_UTF8, 0, lpNewFileName, f2sz, afile2, PATH_MAX, NULL, NULL);
	afile2[count] = 0;
	return tup_rename(afile, afile2);
}

/* -------------------------------------------------------------------------- */

static HFILE WINAPI OpenFile_hook(
    __in    LPCSTR lpFileName,
    __inout LPOFSTRUCT lpReOpenBuff,
    __in    UINT uStyle)
{
	LPCSTR realName;
	if (uStyle & (OF_READWRITE | OF_WRITE | OF_SHARE_DENY_WRITE | OF_SHARE_EXCLUSIVE | OF_CREATE)) {
		realName = tup_get_write(lpFileName);
	} else {
		realName = tup_get_read(lpFileName);
	}

	return OpenFile_orig(
		realName,
		lpReOpenBuff,
		uStyle);
}

/* -------------------------------------------------------------------------- */

#if 0
static HANDLE WINAPI CreateFileA_hook(
    __in     LPCSTR lpFileName,
    __in     DWORD dwDesiredAccess,
    __in     DWORD dwShareMode,
    __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in     DWORD dwCreationDisposition,
    __in     DWORD dwFlagsAndAttributes,
    __in_opt HANDLE hTemplateFile)
{
	HANDLE h;
	LPCSTR realName;

	if (dwDesiredAccess & GENERIC_WRITE) {
		realName = tup_get_write(lpFileName);
	} else {
		realName = tup_get_read(lpFileName);
	}

	h = CreateFileA_orig(
		realName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	DEBUG_HOOK("CreateFileA '%s', %p:%x, %x, %x, %x, %x\n",
		lpFileName,
		h,
		GetLastError(),
		dwDesiredAccess,
		dwShareMode,
		dwCreationDisposition,
		dwFlagsAndAttributes);

	return h;
}


/* -------------------------------------------------------------------------- */

static HANDLE WINAPI CreateFileW_hook(
    __in     LPCWSTR lpFileName,
    __in     DWORD dwDesiredAccess,
    __in     DWORD dwShareMode,
    __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in     DWORD dwCreationDisposition,
    __in     DWORD dwFlagsAndAttributes,
    __in_opt HANDLE hTemplateFile)
{
	HANDLE h;
	LPCSTR realName;
	char buf[PATH_MAX];

	if (dwDesiredAccess & GENERIC_WRITE) {
		realName = tup_get_write_w(lpFileName);
	} else {
		realName = tup_get_read_w(lpFileName, buf);
	}

	h = CreateFileA_orig(
		realName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	return h;
}

/* -------------------------------------------------------------------------- */

HANDLE WINAPI CreateFileTransactedA_hook(
    __in       LPCSTR lpFileName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwShareMode,
    __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in       DWORD dwCreationDisposition,
    __in       DWORD dwFlagsAndAttributes,
    __in_opt   HANDLE hTemplateFile,
    __in       HANDLE hTransaction,
    __in_opt   PUSHORT pusMiniVersion,
    __reserved PVOID  lpExtendedParameter)
{
	HANDLE h;
	LPCSTR realName;

	if (dwDesiredAccess & GENERIC_WRITE) {
		realName = tup_get_write(lpFileName);
	} else {
		realName = tup_get_read(lpFileName);
	}

	h = CreateFileTransactedA_orig(
		realName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile,
		hTransaction,
		pusMiniVersion,
		lpExtendedParameter);

	return h;
}

HANDLE WINAPI CreateFileTransactedW_hook(
    __in       LPCWSTR lpFileName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwShareMode,
    __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __in       DWORD dwCreationDisposition,
    __in       DWORD dwFlagsAndAttributes,
    __in_opt   HANDLE hTemplateFile,
    __in       HANDLE hTransaction,
    __in_opt   PUSHORT pusMiniVersion,
    __reserved PVOID  lpExtendedParameter)
{
	HANDLE h;
	LPCSTR realName;
	char buf[PATH_MAX];

	if (dwDesiredAccess & GENERIC_WRITE) {
		realName = tup_get_write_w(lpFileName);
	} else {
		realName = tup_get_read_w(lpFileName, buf);
	}

	h = CreateFileTransactedA_orig(
		realName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile,
		hTransaction,
		pusMiniVersion,
		lpExtendedParameter);

	return h;
}
#endif

static char *unicode_to_ansi(PUNICODE_STRING uni)
{
	int len;
	char *name = NULL;
	if(!uni)
		return NULL;

	len = WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / sizeof(wchar_t), 0, 0, NULL, NULL);
	if(len > 0) {
		name = malloc(len + 1);
		WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / sizeof(wchar_t), name, len, NULL, NULL);
		name[len] = 0;
	}
	return name;
}

static void ansi_to_unicode(const char *ansi, PUNICODE_STRING uni, int append)
{
	int new_bytes;
	if(!append)
		uni->Length = 0;
	new_bytes = MultiByteToWideChar(CP_UTF8, 0, ansi, -1, uni->Buffer + (uni->Length / sizeof(WCHAR)), uni->MaximumLength - uni->Length);

	/* Adjust for the fact that nul-terminators aren't counted */
	new_bytes--;

	/* Adjust for the fact that MultiByteToWideChar counts unicode characters,
	 * but UNICODE_STRING counts bytes (except for nul-terminators).
	 */
	new_bytes *= sizeof(WCHAR);

	uni->Length += new_bytes;
}

NTSTATUS WINAPI NtCreateFile_hook(
    __out     PHANDLE FileHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt  PLARGE_INTEGER AllocationSize,
    __in      ULONG FileAttributes,
    __in      ULONG ShareAccess,
    __in      ULONG CreateDisposition,
    __in      ULONG CreateOptions,
    __in      PVOID EaBuffer,
    __in      ULONG EaLength)
{
	WCHAR buf[PATH_MAX];
	UNICODE_STRING uni;
	NTSTATUS rc = -1;
	char *ansi;

	uni.Buffer = buf;
	uni.MaximumLength = PATH_MAX * sizeof(WCHAR);

	ansi = unicode_to_ansi(ObjectAttributes->ObjectName);

	if(ansi)  {
		const char *name = ansi;
		LPCSTR realName;
		int questions = 0;

		if(strncmp(name, "\\??\\", 4) == 0) {
			questions = 1;
			name += 4;
			/* Windows started trying to read a file called
			 * "\??\Ip", which broke some of the tests. This just
			 * skips anything that doesn't begin with something
			 * like "C:"
			 */
			if(name[0] != 0 && name[1] != ':')
				goto out_free;
		}

		DEBUG_HOOK("ROOT DIR: %p\n", ObjectAttributes->RootDirectory);
		if(DesiredAccess & GENERIC_WRITE) {
			SECURITY_QUALITY_OF_SERVICE *tmp = ObjectAttributes->SecurityQualityOfService;
			DEBUG_HOOK("Set root dir to NULL\n");
			realName = tup_get_write(name);
			ObjectAttributes->RootDirectory = NULL;
			questions = 1;
			DEBUG_HOOK("NtCreate options: %p, %08x, %p, %p, %08x, %08x, %08x, %i, %08x {%i, %i, %i,}, %08x\n", ObjectAttributes->RootDirectory, ObjectAttributes->Attributes, ObjectAttributes->SecurityDescriptor, ObjectAttributes->SecurityQualityOfService, CreateOptions, CreateDisposition, ShareAccess, EaLength, DesiredAccess, tmp->ImpersonationLevel, tmp->ContextTrackingMode, tmp->EffectiveOnly, AllocationSize);
		} else {
			DEBUG_HOOK("Filename is read\n");
			realName = tup_get_read(name);
		}
		if(questions) {
			ansi_to_unicode("\\??\\", &uni, 0);
		}
		ansi_to_unicode(realName, &uni, questions);
		DEBUG_HOOK("UNI: %ls [%i]\n", uni.Buffer, uni.Length);

		ObjectAttributes->ObjectName = &uni;

		rc = NtCreateFile_orig(FileHandle,
				       DesiredAccess,
				       ObjectAttributes,
				       IoStatusBlock,
				       AllocationSize,
				       FileAttributes,
				       ShareAccess,
				       CreateDisposition,
				       CreateOptions,
				       EaBuffer,
				       EaLength);

		DEBUG_HOOK("ERror: %i\n", GetLastError());
		DEBUG_HOOK("NtCreateFile[%08x] '%s': %x, %x, %x\n", rc, ansi, ShareAccess, DesiredAccess, CreateOptions);
out_free:
		free(ansi);
	}

	return rc;
}

NTSTATUS WINAPI NtOpenFile_hook(
    __out  PHANDLE FileHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG ShareAccess,
    __in   ULONG OpenOptions)
{
	WCHAR buf[PATH_MAX];
	UNICODE_STRING uni;
	NTSTATUS rc = -1;
	char *ansi;

	uni.Buffer = buf;
	uni.MaximumLength = PATH_MAX * sizeof(WCHAR);

	ansi = unicode_to_ansi(ObjectAttributes->ObjectName);
	DEBUG_HOOK("--------------------------\n");
	DEBUG_HOOK("NtOpenFile [%i] (%s)\n", GetCurrentProcessId(), ansi);

	if(ansi) {
		const char *name = ansi;
		LPCSTR realName = NULL;
		int questions = 0;

		DEBUG_HOOK(" -- a\n");
		if(strncmp(name, "\\??\\", 4) == 0) {
			questions = 1;
			name += 4;
			/* Windows started trying to read a file called "\??\Ip",
			 * which broke some of the tests. This just skips
			 * anything that doesn't begin with something like "C:"
			 */
		DEBUG_HOOK(" -- b\n");
			if(name[0] != 0 && name[1] != ':')
				goto out_free;
		DEBUG_HOOK(" -- c\n");
		}

		/* The ShareAccess == FILE_SHARE_DELETE check might be
		 * specific to how cygwin handles unlink(). It is very
		 * confusing to follow, but it doesn't ever seem to go through
		 * the DeleteFile() route. This is the only place I've found
		 * that seems to be able to hook those events.
		 *
		 * The DesiredAccess & DELETE check is how cygwin does a
		 * rename() to remove the old file.
		 */
		if(ShareAccess == FILE_SHARE_DELETE ||
		   DesiredAccess & DELETE) {
			DEBUG_HOOK("NtOpenFile -- delete '%s'\n", name);
			tup_unlink(name);
			goto out_free;
		} else if(OpenOptions & FILE_OPEN_FOR_BACKUP_INTENT) {
			/* The MSVC linker seems to successfully open
			 * "prog.ilk" for reading (when linking "prog.exe"),
			 * even though no such file exists. This confuses tup.
			 * It seems that this flag is used for temporary files,
			 * so that should be safe to ignore.
			 */
			struct mapping *map;
		DEBUG_HOOK(" -- d\n");
			map = mget_mapping(name, &mapping_root);
			if(map) {
				realName = map->tmpname;
		DEBUG_HOOK(" -- e: %s\n", realName);
			}
		} else {
			if (DesiredAccess & GENERIC_WRITE) {
		DEBUG_HOOK(" -- f\n");
				realName = tup_get_write(name);
			} else {
		DEBUG_HOOK(" -- g\n");
				realName = tup_get_read(name);
			}
		}
		if(realName) {
			if(questions) {
				ansi_to_unicode("\\??\\", &uni, 0);
			}
			ansi_to_unicode(realName, &uni, questions);
			DEBUG_HOOK("Previous length: %i\n", ObjectAttributes->ObjectName->Length);
			ObjectAttributes->ObjectName = &uni;
		}

		DEBUG_HOOK(" - open realName: '%s'\n", realName);
		{
			char *tmp;
			tmp = unicode_to_ansi(ObjectAttributes->ObjectName);
			DEBUG_HOOK("TMPTMPTMP[%i, %i]: '%s'\n", ObjectAttributes->ObjectName->Length, ObjectAttributes->ObjectName->MaximumLength, tmp);
			free(tmp);
		}

		rc = NtOpenFile_orig(FileHandle,
				     DesiredAccess,
				     ObjectAttributes,
				     IoStatusBlock,
				     ShareAccess,
				     OpenOptions);
		if(rc == 0) {
			if(add_win_handle_map((unsigned long)*FileHandle, ansi) < 0) {
				SET_ERROR();
				rc = -1;
			}
		}
		DEBUG_HOOK("NtOpenFile[%i] '%s': %x, %x, %x, handle=%p\n", rc, ansi, ShareAccess, DesiredAccess, OpenOptions, *FileHandle);
out_free:
		free(ansi);
	}
	DEBUG_HOOK("------------------------\n");

	return rc;
}

NTSTATUS WINAPI NtQueryDirectoryFile_hook(
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID FileInformation,
    __in      ULONG Length,
    __in      FILE_INFORMATION_CLASS FileInformationClass,
    __in      BOOLEAN ReturnSingleEntry,
    __in_opt  PUNICODE_STRING FileName,
    __in      BOOLEAN RestartScan
)
{
	NTSTATUS rc;
	char *ansi;
	char ansipath[PATH_MAX];
	const char *path;
	int pathlen;
	WCHAR buf[PATH_MAX] = L"UNSET";
	UNICODE_STRING uni;
	HANDLE tmph = INVALID_HANDLE_VALUE;
	struct mapping *map;

	uni.Buffer = buf;
	uni.MaximumLength = PATH_MAX * sizeof(WCHAR);

	path = win_handle_path((unsigned long)FileHandle);
	if(!path) {
		SET_ERROR();
		return -1;
	}
	pathlen = strlen(path);
	if(pathlen >= PATH_MAX) {
		SET_ERROR();
		return -1;
	}

	/* path+4 == skip "\??\" */
	memcpy(ansipath, path+4, pathlen-4);

	ansi = unicode_to_ansi(FileName);
	strcpy(ansipath + pathlen-4, ansi);
	map = get_mapping(ansipath, &mapping_root);
	if(map) {
		const char *lastslash = strrchr(map->tmpname, '\\');
		if(lastslash)
			lastslash++;
		else
			lastslash = map->tmpname;
		ansi_to_unicode(lastslash, &uni, 0);
		FileName = &uni;
		tmph = CreateFile(tmpdir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	} else {
		tmph = FileHandle;
	}
	DEBUG_HOOK("NtQueryDirectoryFile(handle=%p, [%ls] %s, %i, %i, %i)\n", tmph, buf, ansi, ReturnSingleEntry, RestartScan, FileInformationClass);
	free(ansi);
	rc = NtQueryDirectoryFile_orig(tmph,
					 Event,
					 ApcRoutine,
					 ApcContext,
					 IoStatusBlock,
					 FileInformation,
					 Length,
					 FileInformationClass,
					 ReturnSingleEntry,
					 FileName,
					 RestartScan);
	if(tmph != FileHandle) {
		CloseHandle(tmph);
	}
	DEBUG_HOOK(" -- query rc: %08x\n", rc);
	return rc;
}


BOOL WINAPI DeleteFileA_hook(
    __in LPCSTR lpFileName)
{
	return tup_unlink(lpFileName);
}

BOOL WINAPI DeleteFileW_hook(
    __in LPCWSTR lpFileName)
{
	return tup_unlink_w(lpFileName);
}

BOOL WINAPI DeleteFileTransactedA_hook(
    __in     LPCSTR lpFileName,
    __in     HANDLE hTransaction)
{
	(void)hTransaction;
	return tup_unlink(lpFileName);
}

BOOL WINAPI DeleteFileTransactedW_hook(
    __in     LPCWSTR lpFileName,
    __in     HANDLE hTransaction)
{
	(void)hTransaction;
	return tup_unlink_w(lpFileName);
}

BOOL WINAPI MoveFileA_hook(
    __in LPCSTR lpExistingFileName,
    __in LPCSTR lpNewFileName)
{
	return tup_rename(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileW_hook(
    __in LPCWSTR lpExistingFileName,
    __in LPCWSTR lpNewFileName)
{
	return tup_rename_w(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileExA_hook(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in     DWORD    dwFlags)
{
	(void)dwFlags;
	return tup_rename(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileExW_hook(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in     DWORD    dwFlags)
{
	(void)dwFlags;
	return tup_rename_w(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileWithProgressA_hook(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags)
{
	(void)lpProgressRoutine;
	(void)lpData;
	(void)dwFlags;
	return tup_rename(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileWithProgressW_hook(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags)
{
	(void)lpProgressRoutine;
	(void)lpData;
	(void)dwFlags;
	return tup_rename_w(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileTransactedA_hook(
    __in     LPCSTR lpExistingFileName,
    __in_opt LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags,
    __in     HANDLE hTransaction)
{
	(void)lpProgressRoutine;
	(void)lpData;
	(void)dwFlags;
	(void)hTransaction;
	return tup_rename(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI MoveFileTransactedW_hook(
    __in     LPCWSTR lpExistingFileName,
    __in_opt LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in     DWORD dwFlags,
    __in     HANDLE hTransaction)
{
	(void)lpProgressRoutine;
	(void)lpData;
	(void)dwFlags;
	(void)hTransaction;
	return tup_rename_w(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI ReplaceFileA_hook(
    __in       LPCSTR  lpReplacedFileName,
    __in       LPCSTR  lpReplacementFileName,
    __in_opt   LPCSTR  lpBackupFileName,
    __in       DWORD   dwReplaceFlags,
    __reserved LPVOID  lpExclude,
    __reserved LPVOID  lpReserved)
{
	(void)lpBackupFileName;
	(void)dwReplaceFlags;
	(void)lpExclude;
	(void)lpReserved;
	return tup_rename(lpReplacementFileName, lpReplacedFileName);
}

BOOL WINAPI ReplaceFileW_hook(
    __in       LPCWSTR lpReplacedFileName,
    __in       LPCWSTR lpReplacementFileName,
    __in_opt   LPCWSTR lpBackupFileName,
    __in       DWORD   dwReplaceFlags,
    __reserved LPVOID  lpExclude,
    __reserved LPVOID  lpReserved)
{
	(void)lpBackupFileName;
	(void)dwReplaceFlags;
	(void)lpExclude;
	(void)lpReserved;
	return tup_rename_w(lpReplacementFileName, lpReplacedFileName);
}

BOOL WINAPI CopyFileA_hook(
    __in LPCSTR lpExistingFileName,
    __in LPCSTR lpNewFileName,
    __in BOOL bFailIfExists)
{
	LPCSTR readFile = tup_get_read(lpExistingFileName);
	LPCSTR writeFile = tup_get_write(lpNewFileName);

	return CopyFileA_orig(
		readFile,
		writeFile,
		bFailIfExists);
}

BOOL WINAPI CopyFileW_hook(
    __in LPCWSTR lpExistingFileName,
    __in LPCWSTR lpNewFileName,
    __in BOOL bFailIfExists)
{
	char buf[PATH_MAX];
	LPCSTR readFile = tup_get_read_w(lpExistingFileName, buf);
	LPCSTR writeFile = tup_get_write_w(lpNewFileName);

	return CopyFileA_orig(
		readFile,
		writeFile,
		bFailIfExists);
}

BOOL WINAPI CopyFileExA_hook(
    __in     LPCSTR lpExistingFileName,
    __in     LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags)
{
	LPCSTR readFile = tup_get_read(lpExistingFileName);
	LPCSTR writeFile = tup_get_write(lpNewFileName);

	return CopyFileExA_orig(
		readFile,
		writeFile,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags);
}

BOOL WINAPI CopyFileExW_hook(
    __in     LPCWSTR lpExistingFileName,
    __in     LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags)
{
	char buf[PATH_MAX];
	LPCSTR readFile = tup_get_read_w(lpExistingFileName, buf);
	LPCSTR writeFile = tup_get_write_w(lpNewFileName);

	return CopyFileExA_orig(
		readFile,
		writeFile,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags);
}

BOOL WINAPI CopyFileTransactedA_hook(
    __in     LPCSTR lpExistingFileName,
    __in     LPCSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags,
    __in     HANDLE hTransaction)
{
	LPCSTR readFile = tup_get_read(lpExistingFileName);
	LPCSTR writeFile = tup_get_write(lpNewFileName);

	return CopyFileTransactedA_orig(
		readFile,
		writeFile,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags,
		hTransaction);
}

BOOL WINAPI CopyFileTransactedW_hook(
    __in     LPCWSTR lpExistingFileName,
    __in     LPCWSTR lpNewFileName,
    __in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt LPVOID lpData,
    __in_opt LPBOOL pbCancel,
    __in     DWORD dwCopyFlags,
    __in     HANDLE hTransaction)
{
	char buf[PATH_MAX];
	LPCSTR readFile = tup_get_read_w(lpExistingFileName, buf);
	LPCSTR writeFile = tup_get_write_w(lpNewFileName);

	return CopyFileTransactedA_orig(
		readFile,
		writeFile,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags,
		hTransaction);
}

#define ATTRIB_FAIL 0xffffffff
DWORD WINAPI GetFileAttributesA_hook(
    __in LPCSTR lpFileName)
{
	DWORD attributes;
	LPCSTR readFile = tup_get_read_no_handle(lpFileName);

	attributes = GetFileAttributesA_orig(readFile);
	DEBUG_HOOK("GetFileAttributesA '%s'\n", lpFileName);

	/* If it fails (attributes == -1), we need to handle the read since
	 * it will be a ghost. If the file exists, we only care if it's a file
	 * and not a directory.
	 */
	if(attributes == ATTRIB_FAIL || ! (attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file(lpFileName, NULL, ACCESS_READ);
	return attributes;
}

DWORD WINAPI GetFileAttributesW_hook(
    __in LPCWSTR lpFileName)
{
	DWORD attributes;
	char buf[PATH_MAX];
	LPCSTR readFile = tup_get_read_no_handle_w(lpFileName, buf);

	attributes = GetFileAttributesA_orig(readFile);
	if(attributes == ATTRIB_FAIL || ! (attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file_w(lpFileName, NULL, ACCESS_READ);
	return attributes;
}

BOOL WINAPI GetFileAttributesExA_hook(
    __in  LPCSTR lpFileName,
    __in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    __out LPVOID lpFileInformation)
{
	DWORD attributes;
	LPCSTR readFile = tup_get_read_no_handle(lpFileName);

	attributes = GetFileAttributesExA_orig(
		readFile,
		fInfoLevelId,
		lpFileInformation);
	if(attributes == ATTRIB_FAIL || ! (attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file(lpFileName, NULL, ACCESS_READ);
	return attributes;
}

BOOL WINAPI GetFileAttributesExW_hook(
    __in  LPCWSTR lpFileName,
    __in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    __out LPVOID lpFileInformation)
{
	DWORD attributes;
	char buf[PATH_MAX];
	LPCSTR readFile = tup_get_read_no_handle_w(lpFileName, buf);

	attributes = GetFileAttributesExA_orig(
		readFile,
		fInfoLevelId,
		lpFileInformation);
	if(attributes == ATTRIB_FAIL || ! (attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file_w(lpFileName, NULL, ACCESS_READ);
	return attributes;
}

__out HANDLE WINAPI FindFirstFileA_hook(
    __in  LPCSTR lpFileName,
    __out LPWIN32_FIND_DATAA lpFindFileData)
{
	DEBUG_HOOK("FindFirstFileA '%s'\n", lpFileName);
	return FindFirstFileA_orig(lpFileName, lpFindFileData);
}

__out HANDLE WINAPI FindFirstFileW_hook(
    __in  LPCWSTR lpFileName,
    __out LPWIN32_FIND_DATAW lpFindFileData)
{
	DEBUG_HOOK("FindFirstFileW '%S'\n", lpFileName);
	return FindFirstFileW_orig(lpFileName, lpFindFileData);
}

BOOL WINAPI FindNextFileA_hook(
    __in  HANDLE hFindFile,
    __out LPWIN32_FIND_DATAA lpFindFileData)
{
	if (!FindNextFileA_orig(hFindFile, lpFindFileData))
		return 0;

	DEBUG_HOOK("FindNextFileA '%s'\n", lpFindFileData->cFileName);
	return 1;
}

BOOL WINAPI FindNextFileW_hook(
    __in  HANDLE hFindFile,
    __out LPWIN32_FIND_DATAW lpFindFileData)
{
	if (!FindNextFileW_orig(hFindFile, lpFindFileData))
		return 0;

	DEBUG_HOOK("FindNextFileW '%S'\n", lpFindFileData->cFileName);
	return 1;
}

BOOL WINAPI CreateProcessA_hook(
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessA_orig(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessA '%s' '%s' in '%s'\n",
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(strcasestr(lpApplicationName, "mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

BOOL WINAPI CreateProcessW_hook(
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessW_orig(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessW %x '%S' '%S' in '%S'\n",
		dwCreationFlags,
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(wcscasestr(lpApplicationName, L"mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

BOOL WINAPI CreateProcessAsUserA_hook(
    __in_opt    HANDLE hToken,
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessAsUserA_orig(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessAsUserA '%s' '%s' in '%s'\n",
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(strcasestr(lpApplicationName, "mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

BOOL WINAPI CreateProcessAsUserW_hook(
    __in_opt    HANDLE hToken,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessAsUserW_orig(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessAsUserW '%S' '%S' in '%S'\n",
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(wcscasestr(lpApplicationName, L"mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

BOOL WINAPI CreateProcessWithLogonW_hook(
    __in        LPCWSTR lpUsername,
    __in_opt    LPCWSTR lpDomain,
    __in        LPCWSTR lpPassword,
    __in        DWORD dwLogonFlags,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessWithLogonW_orig(
		lpUsername,
		lpDomain,
		lpPassword,
		dwLogonFlags,
		lpApplicationName,
		lpCommandLine,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessWithLogonW '%S' '%S' in '%S'\n",
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(wcscasestr(lpApplicationName, L"mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

BOOL WINAPI CreateProcessWithTokenW_hook(
    __in        HANDLE hToken,
    __in        DWORD dwLogonFlags,
    __in_opt    LPCWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOW lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
	BOOL ret = CreateProcessWithTokenW_orig(
		hToken,
		dwLogonFlags,
		lpApplicationName,
		lpCommandLine,
		dwCreationFlags | CREATE_SUSPENDED,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	DEBUG_HOOK("CreateProcessWithTokenW '%S' '%S' in '%S'\n",
		lpApplicationName,
		lpCommandLine,
		lpCurrentDirectory);

	if (!ret) {
		return 0;
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(wcscasestr(lpApplicationName, L"mspdbsrv.exe") == NULL)
		tup_inject_dll(lpProcessInformation, s_depfilename, sid);

	if ((dwCreationFlags & CREATE_SUSPENDED) != 0)
		return 1;

	return ResumeThread(lpProcessInformation->hThread) != 0xFFFFFFFF;
}

int _access_hook(const char *pathname, int mode)
{
	LPCSTR realName = tup_get_read(pathname);
	return _access_orig(realName, mode);
}

FILE *fopen_hook(const char *path, const char *mode)
{
	LPCSTR realName;
	DEBUG_HOOK("fopen mode = %s\n", mode );

	if(strchr(mode, 'w') == NULL &&
	   strchr(mode, 'a') == NULL &&
	   strchr(mode, '+') == NULL) {
		realName = tup_get_read(path);
	} else {
		return fopen_orig(path, mode);
//		realName = tup_get_write(path);
	}
	return fopen_orig(realName, mode);
}

int rename_hook(const char *oldpath, const char *newpath)
{
	return tup_rename(oldpath, newpath);
}

int remove_hook(const char *pathname)
{
	return tup_unlink(pathname);
}

/* -------------------------------------------------------------------------- */


typedef HMODULE (WINAPI *LoadLibraryA_t)(const char*);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, const char*);

struct remote_thread_t {
	LoadLibraryA_t load_library;
	GetProcAddress_t get_proc_address;
	int sid;
	char depfilename[MAX_PATH];
	char execdir[MAX_PATH];
	char dll_name[MAX_PATH];
	char tmpdir[MAX_PATH];
	char func_name[256];
};


typedef void (*foreach_import_t)(HMODULE, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur);
static void foreach_module(HMODULE h, foreach_import_t kernel32, foreach_import_t advapi32, foreach_import_t nt, foreach_import_t msvcrt)
{
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	IMAGE_DATA_DIRECTORY* import_dir;
	IMAGE_IMPORT_DESCRIPTOR* imports;

	dos_header = (IMAGE_DOS_HEADER*) h;
	nt_headers = (IMAGE_NT_HEADERS*) (dos_header->e_lfanew + (char*) h);

	import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	imports = (IMAGE_IMPORT_DESCRIPTOR*) (import_dir->VirtualAddress + (char*) h);
	if (import_dir->VirtualAddress == 0)
		return;

	while (imports->Name != 0) {
		char* dllname = (char*) h + imports->Name;
		if (imports->FirstThunk && imports->OriginalFirstThunk) {
			IMAGE_THUNK_DATA* cur = (IMAGE_THUNK_DATA*) (imports->FirstThunk + (char*) h);
			IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*) (imports->OriginalFirstThunk + (char*) h);
			if (stricmp(dllname, "kernel32.dll") == 0) {
				while (cur->u1.Function && orig->u1.Function) {
					kernel32(h, orig, cur);
					cur++;
					orig++;
				}
			} else if (stricmp(dllname, "advapi32.dll") == 0) {
				while (cur->u1.Function && orig->u1.Function) {
					advapi32(h, orig, cur);
					cur++;
					orig++;
				}
			} else if (stricmp(dllname, "ntdll.dll") == 0) {
				while (cur->u1.Function && orig->u1.Function) {
					nt(h, orig, cur);
					cur++;
					orig++;
				}
			} else if(stricmp(dllname, "msvcrt.dll") == 0) {
				while (cur->u1.Function && orig->u1.Function) {
					msvcrt(h, orig, cur);
					cur++;
					orig++;
				}
			}
		}
		imports++;
	}
}

static void do_hook(void* fphook, void** fporig, IMAGE_THUNK_DATA* cur)
{
	DWORD old_protect;
	*fporig = (void*) cur->u1.Function;
	if (!VirtualProtect(cur, sizeof(IMAGE_THUNK_DATA), PAGE_EXECUTE_READWRITE, &old_protect)) {
		return;
	}

	cur->u1.Function = (uintptr_t) fphook;

	if (!VirtualProtect(cur, sizeof(IMAGE_THUNK_DATA), old_protect, &old_protect)) {
		return;
	}
}

static void hook(HMODULE h, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur, void* fphook, void** fporig, const char* wanted_name, DWORD wanted_ordinal)
{
	if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
		DWORD ordinal = orig->u1.Ordinal & ~IMAGE_ORDINAL_FLAG;
		if (ordinal == wanted_ordinal) {
			do_hook(fphook, fporig, cur);
		}
	} else {
		IMAGE_IMPORT_BY_NAME* name = (IMAGE_IMPORT_BY_NAME*) (orig->u1.AddressOfData + (char*) h);
		if (strcmp((const char*) name->Name, wanted_name) == 0) {
			do_hook(fphook, fporig, cur);
		}
	}
}

#define HOOK_ORD(name, ordinal) hook(h, orig, cur, (void*) name##_hook, (void**) &name##_orig, #name, ordinal)
#define HOOK(name) hook(h, orig, cur, (void*) name##_hook, (void**) &name##_orig, #name, IMAGE_ORDINAL_FLAG)

static void have_kernel32_import(HMODULE h, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur)
{
	HOOK(OpenFile);
#if 0
	HOOK(CreateFileA);
	HOOK(CreateFileW);
	HOOK(CreateFileTransactedA);
	HOOK(CreateFileTransactedW);
#endif
	HOOK(DeleteFileA);
	HOOK(DeleteFileW);
	HOOK(DeleteFileTransactedA);
	HOOK(DeleteFileTransactedW);
	HOOK(MoveFileA);
	HOOK(MoveFileW);
	HOOK(MoveFileExA);
	HOOK(MoveFileExW);
	HOOK(MoveFileWithProgressA);
	HOOK(MoveFileWithProgressW);
	HOOK(MoveFileTransactedA);
	HOOK(MoveFileTransactedW);
	HOOK(ReplaceFileA);
	HOOK(ReplaceFileW);
	HOOK(CopyFileA);
	HOOK(CopyFileW);
	HOOK(CopyFileExA);
	HOOK(CopyFileExW);
	HOOK(CopyFileTransactedA);
	HOOK(CopyFileTransactedW);
	HOOK(GetFileAttributesA);
	HOOK(GetFileAttributesW);
	HOOK(GetFileAttributesExA);
	HOOK(GetFileAttributesExW);
	HOOK(FindFirstFileA);
	HOOK(FindFirstFileW);
	HOOK(FindNextFileA);
	HOOK(FindNextFileW);
	HOOK(CreateProcessA);
	HOOK(CreateProcessW);
}

static void have_advapi32_import(HMODULE h, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur)
{
	HOOK(CreateProcessAsUserA);
	HOOK(CreateProcessAsUserW);
	HOOK(CreateProcessWithLogonW);
	HOOK(CreateProcessWithTokenW);
}

static void have_nt_import(HMODULE h, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur)
{
	if(h || orig || cur) {}
	HOOK(NtCreateFile);
	HOOK(NtOpenFile);
	HOOK(NtQueryDirectoryFile);
}

static void have_msvcrt_import(HMODULE h, IMAGE_THUNK_DATA* orig, IMAGE_THUNK_DATA* cur)
{
	HOOK(_access);
	HOOK(fopen);
	HOOK(rename);
	HOOK(remove);
}

/* -------------------------------------------------------------------------- */

void tup_inject_setexecdir(const char* dir, const char *newtmpdir)
{
	execdir[0] = '\0';
	strncat(execdir, dir, MAX_PATH);
	execdir[MAX_PATH - 1] = '\0';

	tmpdir[0] = '\0';
	strncat(tmpdir, newtmpdir, MAX_PATH);
	tmpdir[MAX_PATH - 1] = '\0';
}

/* -------------------------------------------------------------------------- */

static const char *strcasestr(const char *arg1, const char *arg2)
{
	const char *a, *b;

	for(;*arg1;arg1++) {

		a = arg1;
		b = arg2;

		while(tolower(*a++) == tolower(*b++)) {
			if(!*b) {
				return (arg1);
			}
		}

	}

	return(NULL);
}

static const wchar_t *wcscasestr(const wchar_t *arg1, const wchar_t *arg2)
{
	const wchar_t *a, *b;

	for(;*arg1;arg1++) {

		a = arg1;
		b = arg2;

		while(tolower(*a++) == tolower(*b++)) {
			if(!*b) {
				return (arg1);
			}
		}

	}

	return(NULL);
}

static int ignore_file(const char* file)
{
	if (!file)
		return 0;
	if (stricmp(file, "nul") == 0)
		return 1;
	if (stricmp(file, "prn") == 0)
		return 1;
	if (stricmp(file, "aux") == 0)
		return 1;
	if (stricmp(file, "con") == 0)
		return 1;
	if (strncmp(file, "com", 3) == 0 && isdigit(file[3]) && file[4] == '\0')
		return 1;
	if (strncmp(file, "lpt", 3) == 0 && isdigit(file[3]) && file[4] == '\0')
		return 1;
	if (strcasestr(file, "\\PIPE\\") != NULL)
		return 1;
	if (strnicmp(file, "PIPE\\", 5) == 0)
		return 1;
	if (strcasestr(file, "\\Device\\") != NULL)
		return 1;
	if (strstr(file, "$") != NULL)
		return 1;
	return 0;
}

static int ignore_file_w(const wchar_t* file)
{
	if (!file)
		return 0;
	if (wcsicmp(file, L"nul") == 0)
		return 1;
	if (wcsicmp(file, L"prn") == 0)
		return 1;
	if (wcsicmp(file, L"aux") == 0)
		return 1;
	if (wcsicmp(file, L"con") == 0)
		return 1;
	if (wcsncmp(file, L"com", 3) == 0 && isdigit(file[3]) && file[4] == L'\0')
		return 1;
	if (wcsncmp(file, L"lpt", 3) == 0 && isdigit(file[3]) && file[4] == L'\0')
		return 1;
	if (wcscasestr(file, L"\\PIPE\\") != NULL)
		return 1;
	if (wcsstr(file, L"$") != NULL)
		return 1;
	return 0;
}

static int canon_path(const char *file, char *dest)
{
	if(!file || !file[0])
		return 0;
	if(is_full_path(file)) {
		/* Full path */
		PathCanonicalize(dest, file);
	} else {
		/* Relative path */
		char tmp[PATH_MAX];
		int cwdlen;
		int filelen = strlen(file);

		tmp[0] = 0;
		if(GetCurrentDirectory(sizeof(tmp), tmp) == 0) {
			/* TODO: Error handle? */
			return 0;
		}
		cwdlen = strlen(tmp);
		if(cwdlen + filelen + 2 >= (signed)sizeof(tmp)) {
			/* TODO: Error handle? */
			return 0;
		}
		tmp[cwdlen] = '\\';
		memcpy(tmp + cwdlen + 1, file, filelen + 1);
		PathCanonicalize(dest, tmp);
	}
	return strlen(dest);
}

static void mhandle_file(const char* file, const char* file2, enum access_type at, int line)
{
	DWORD save_error = GetLastError();

	char buf[ACCESS_EVENT_MAX_SIZE];
	struct access_event* e = (struct access_event*) buf;
	char* dest = (char*) (e + 1);
	int ret;
	if(line) {}

	if (ignore_file(file) || ignore_file(file2) || depf == NULL)
		goto exit;

	e->at = at;

	e->len = canon_path(file, dest);
	DEBUG_HOOK("Canonicalize1 [%i]: '%s' -> '%s', len=%i\n", line, file, dest, e->len);
	dest += e->len;
	*(dest++) = '\0';

	e->len2 = canon_path(file2, dest);
	DEBUG_HOOK("Canonicalize2: '%s' -> '%s' len2=%i\n", file2, file2 ? dest : NULL, e->len2);
	dest += e->len2;
	*(dest++) = '\0';

	DEBUG_HOOK("%s: '%s' '%s'\n", access_type_name[at], file, file2);
	ret = writef((char*) e, dest - (char*) e);
	DEBUG_HOOK("writef %d\n", ret);
	if(ret) {}

exit:;
	SetLastError( save_error );
}

static void mhandle_file_w(const wchar_t* file, const wchar_t* file2, enum access_type at, int line)
{
	DWORD save_error = GetLastError();

	char buf[ACCESS_EVENT_MAX_SIZE];
	char afile[PATH_MAX];
	char afile2[PATH_MAX];
	size_t fsz = file ? wcslen(file) : 0;
	size_t f2sz = file2 ? wcslen(file2) : 0;
	struct access_event* e = (struct access_event*) buf;
	char* dest = (char*) (e + 1);
	int ret;
	int count;
	if(line) {}

	if (ignore_file_w(file) || ignore_file_w(file2) || depf == NULL)
		goto exit;

	e->at = at;

	count = WideCharToMultiByte(CP_UTF8, 0, file, fsz, afile, PATH_MAX, NULL, NULL);
	afile[count] = 0;
	count = WideCharToMultiByte(CP_UTF8, 0, file2, f2sz, afile2, PATH_MAX, NULL, NULL);
	afile2[count] = 0;

	e->len = canon_path(afile, dest);
	dest += e->len;
	*(dest++) = '\0';

	e->len2 = canon_path(afile2, dest);
	dest += e->len2;
	*(dest++) = '\0';

	DEBUG_HOOK("%s line=%i [wide, %i, %i]: '%S', '%S'\n", access_type_name[at], line, e->len, e->len2, file, file2);
	ret = writef((char*) e, dest - (char*) e);
	DEBUG_HOOK("writef [wide] %d\n", ret);
	if(ret) {}

exit:;
	SetLastError( save_error );
}

static int open_file(const char *depfilename)
{
	depf = fopen(depfilename, "rb+");
	if(!depf) {
		perror(depfilename);
		return -1;
	}

/*	deph = CreateFile(depfilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if(deph == INVALID_HANDLE_VALUE) {
		perror(depfilename);
		return -1;
	}*/
	return 0;
}

/* -------------------------------------------------------------------------- */

BOOL WINAPI DllMain(HANDLE HDllHandle, DWORD Reason, LPVOID Reserved)
{
	(void)HDllHandle;
	(void)Reason;
	(void)Reserved;
	return 1;
}

/* -------------------------------------------------------------------------- */

typedef DWORD (*tup_init_t)(remote_thread_t*);
DWORD tup_inject_init(remote_thread_t* r)
{
	static int initialised = 0;

	size_t i;
	DWORD modnum;
	HMODULE modules[256];
	char filename[MAX_PATH];

	if (initialised)
		return 0;

	/* Put TUP_VARDICT_NAME in the environment so if tup is running as the
	 * sub-process it knows that certain commands are unavailable. Note
	 * this isn't actually a valid file id, so varsed and all will fail.
	 */
	putenv(TUP_VARDICT_NAME "=-1");

	initialised = 1;

	if (!GetModuleFileNameA(NULL, filename, sizeof(filename))) {
		return 1;
	}

	DEBUG_HOOK("Inside tup_dllinject_init '%s' '%s' '%s' '%s' '%s'\n",
		filename,
		r->execdir,
		r->dll_name,
		r->func_name,
		r->depfilename);

	DEBUG_HOOK("%d: %s\n", GetCurrentProcessId(), GetCommandLineA());

	if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &modnum)) {
		return 1;
	}

	modnum /= sizeof(HMODULE);

	tup_inject_setexecdir(r->execdir, r->tmpdir);

	if (open_file(r->depfilename))
		return 1;

	strcpy(s_depfilename, r->depfilename);

	sid = r->sid;

	handle_file(filename, NULL, ACCESS_READ);

	for (i = 0; i < modnum; i++) {
		if (!GetModuleFileNameA(modules[i], filename, sizeof(filename))) {
			return 1;
		}
		handle_file(filename, NULL, ACCESS_READ);

		foreach_module(modules[i], &have_kernel32_import, &have_advapi32_import, &have_nt_import, &have_msvcrt_import);
	}

	return 0;
}

int remote_stub(void);
__asm(
  ".globl _remote_stub\n"
  "_remote_stub:\n"
  "pushl $0xDEADBEEF\n"    // return address, [1]
  "pushfl\n"
  "pushal\n"
  "pushl $0xDEADBEEF\n"    // function parameter, [8]
  "movl $0xDEADBEEF, %eax\n" // function to call, [13]
  "call *%eax\n"
  "popal\n"
  "popfl\n"
  "ret"
);

static void WINAPI remote_init( remote_thread_t *r )
{
	HMODULE h;
	tup_init_t p;
	h = r->load_library(r->dll_name);
	if (!h)
		return;

	p = (tup_init_t) r->get_proc_address(h, r->func_name);
	if (!p)
		return;

	p(r);
}

static void remote_end(void)
{
}

int tup_inject_dll(
	LPPROCESS_INFORMATION lpProcessInformation,
	const char *depfilename,
	int newsid)
{
	remote_thread_t remote;
	char* remote_data;
	size_t code_size;
	DWORD old_protect;
	HANDLE process;
	HMODULE kernel32;

	memset(&remote, 0, sizeof(remote));
	kernel32 = LoadLibraryA("kernel32.dll");
	remote.load_library = (LoadLibraryA_t) GetProcAddress(kernel32, "LoadLibraryA");
	remote.get_proc_address = (GetProcAddress_t) GetProcAddress(kernel32, "GetProcAddress");
	strcpy(remote.depfilename, depfilename);
	strcat(remote.execdir, execdir);
	strcat(remote.dll_name, execdir);
	strcat(remote.dll_name, "\\");
	strcat(remote.dll_name, "tup-dllinject.dll");
	strcat(remote.func_name, "tup_inject_init");
	strcat(remote.tmpdir, tmpdir);
	remote.sid = newsid;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if( !GetThreadContext( lpProcessInformation->hThread, &ctx ) )
		return -1;

	DEBUG_HOOK("Injecting dll '%s' '%s' %s' '%s'\n",
		remote.execdir,
		remote.dll_name,
		remote.func_name,
		remote.depfilename);

	process = lpProcessInformation->hProcess;

	if (!WaitForInputIdle(process, INFINITE))
		return -1;

	/* Align code_size to a 16 byte boundary */
	code_size = (  (uintptr_t) &remote_end
		     - (uintptr_t) &remote_stub + 0x0F)
		  & ~0x0F;

	remote_data = (char*) VirtualAllocEx(
		process,
		NULL,
		code_size + sizeof(remote),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!remote_data)
		return -1;

	if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_READWRITE, &old_protect))
		return -1;

	unsigned char code[code_size];
	memcpy( code, &remote_stub, code_size );
	*(DWORD*)(code + 1) = ctx.Eip;
	*(DWORD*)(code + 8) = (DWORD)remote_data + code_size;
	*(DWORD*)(code + 13) = (DWORD)remote_data + ( (DWORD)&remote_init - (DWORD)&remote_stub );
	if (!WriteProcessMemory(process, remote_data, code, code_size, NULL))
		return -1;

	if (!WriteProcessMemory(process, remote_data + code_size, &remote, sizeof(remote), NULL))
		return -1;

	if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_EXECUTE_READ, &old_protect))
		return -1;

	if (!FlushInstructionCache(process, remote_data, code_size + sizeof(remote)))
		return -1;

	ctx.Eip = (DWORD)remote_data;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if( !SetThreadContext( lpProcessInformation->hThread, &ctx ) )
        return -1;

	return 0;
}
