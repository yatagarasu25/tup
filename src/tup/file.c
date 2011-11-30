/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2008-2012  Mike Shal <marfey@gmail.com>
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

#define _ATFILE_SOURCE
#include "file.h"
#include "access_event.h"
#include "mapping.h"
#include "debug.h"
#include "db.h"
#include "fileio.h"
#include "config.h"
#include "entry.h"
#include "option.h"
#include "container.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

static struct file_entry *new_entry(const char *filename, int len);
static void del_entry(struct file_entry *fent, struct string_entries *root);
static int update_write_info(FILE *f, tupid_t cmdid, struct file_info *info,
			     int *warnings, struct tup_entry_head *entryhead);
static int update_read_info(FILE *f, tupid_t cmdid, struct file_info *info,
			    struct tup_entry_head *entryhead,
			    struct tupid_entries *sticky_root,
			    struct tupid_entries *normal_root, int full_deps, tupid_t vardt);
static int add_config_files_locked(struct file_info *finfo, struct tup_entry *tent);
static int add_parser_files_locked(FILE *f, struct file_info *finfo,
				   struct tupid_entries *root, tupid_t vardt);

int init_file_info(struct file_info *info, const char *variant_dir)
{
	RB_INIT(&info->read_root);
	RB_INIT(&info->var_root);
	RB_INIT(&info->mapping_root);
	LIST_INIT(&info->tmpdir_list);
	pthread_mutex_init(&info->lock, NULL);
	/* Root variant gets a NULL variant_dir so we can skip trying to do the
	 * same thing twice in the server (eg: we only need a single readdir()
	 * on the src tree).
	 */
	if(variant_dir[0])
		info->variant_dir = variant_dir;
	else
		info->variant_dir = NULL;
	info->server_fail = 0;
	return 0;
}

void finfo_lock(struct file_info *info)
{
	pthread_mutex_lock(&info->lock);
}

void finfo_unlock(struct file_info *info)
{
	pthread_mutex_unlock(&info->lock);
}

int handle_file(enum access_type at, const char *filename, struct file_info *info)
{
	DEBUGP("received file '%s' in mode %i\n", filename, at);
	int rc;

	finfo_lock(info);
	rc = handle_open_file(at, filename, info);
	finfo_unlock(info);

	return rc;
}

static int handle_read(const char *filename, struct file_info *info)
{
	struct file_entry *fent;
	int len = strlen(filename);

	if(string_tree_search(&info->read_root, filename, len) ||
	   string_tree_search(&info->mapping_root, filename, len)) {
		/* If we already have it in the read or write trees, we're good */
		return 0;
	}
	fent = new_entry(filename, len);
	if(!fent)
		return -1;
	if(string_tree_insert(&info->read_root, &fent->filename) < 0) {
		fprintf(stderr, "tup internal error: Unable to insert filename into read_root\n");
		return -1;
	}
	return 0;
}

static int handle_var(const char *filename, struct file_info *info)
{
	struct file_entry *fent;
	int len = strlen(filename);

	if(string_tree_search(&info->var_root, filename, len)) {
		/* If we already accessed the var, we're good. */
		return 0;
	}
	fent = new_entry(filename, len);
	if(!fent)
		return -1;
	if(string_tree_insert(&info->var_root, &fent->filename) < 0) {
		fprintf(stderr, "tup internal error: Unable to insert variable entry into var_root\n");
		return -1;
	}
	return 0;
}

int handle_open_file(enum access_type at, const char *filename,
		     struct file_info *info)
{
	int rc = 0;

	switch(at) {
		case ACCESS_READ:
			rc = handle_read(filename, info);
			break;
		case ACCESS_VAR:
			rc = handle_var(filename, info);
			break;
		case ACCESS_WRITE:
		case ACCESS_UNLINK:
		case ACCESS_RENAME:
		default:
			fprintf(stderr, "Invalid event type: %i\n", at);
			rc = -1;
			break;
	}

	return rc;
}

void ignore_read_file(const char *filename, int len, struct file_info *info)
{
	struct string_tree *st;
	st = string_tree_search(&info->read_root, filename, len);
	if(st) {
		struct file_entry *fent;
		fent = container_of(st, struct file_entry, filename);
		del_entry(fent, &info->read_root);
	}
}

int write_files(FILE *f, tupid_t cmdid, struct file_info *info, int *warnings,
		int check_only, struct tupid_entries *sticky_root,
		struct tupid_entries *normal_root, int full_deps, tupid_t vardt)
{
	struct tup_entry_head *entrylist;
	struct tmpdir *tmpdir;
	int tmpdir_bork = 0;
	int rc1 = 0, rc2;

	finfo_lock(info);

	if(!check_only) {
		LIST_FOREACH(tmpdir, &info->tmpdir_list, list) {
			fprintf(f, "tup error: Directory '%s' was created, but not subsequently removed. Only temporary directories can be created by commands.\n", tmpdir->dirname);
			tmpdir_bork = 1;
		}
		if(tmpdir_bork) {
			finfo_unlock(info);
			return -1;
		}

		entrylist = tup_entry_get_list();
		rc1 = update_write_info(f, cmdid, info, warnings, entrylist);
		tup_entry_release_list();
	}

	entrylist = tup_entry_get_list();
	rc2 = update_read_info(f, cmdid, info, entrylist, sticky_root, normal_root, full_deps, vardt);
	tup_entry_release_list();
	finfo_unlock(info);

	if(rc1 == 0 && rc2 == 0)
		return 0;
	return -1;
}

int add_config_files(struct file_info *finfo, struct tup_entry *tent)
{
	int rc;
	finfo_lock(finfo);
	rc = add_config_files_locked(finfo, tent);
	finfo_unlock(finfo);
	return rc;
}

int add_parser_files(FILE *f, struct file_info *finfo, struct tupid_entries *root, tupid_t vardt)
{
	int rc;
	finfo_lock(finfo);
	rc = add_parser_files_locked(f, finfo, root, vardt);
	finfo_unlock(finfo);
	return rc;
}

/* Ghost directories in the /-tree have mtimes set to zero if they exist. This way we can
 * distinguish between a directory being created where there wasn't one previously (t4064).
 */
static int set_directories_to_zero(tupid_t dt, tupid_t slash)
{
	struct tup_entry *tent;

	if(dt == slash)
		return 0;
	if(tup_entry_add(dt, &tent) < 0)
		return -1;

	/* Short circuit if we found a dir that is already set */
	if(tent->mtime == 0)
		return 0;

	if(tup_db_set_mtime(tent, 0) < 0)
		return -1;
	return set_directories_to_zero(tent->dt, slash);
}

static int add_node_to_list(FILE *f, tupid_t dt, struct pel_group *pg,
			    struct tup_entry_head *head, int full_deps, const char *full_path)
{
	tupid_t new_dt;
	struct path_element *pel = NULL;
	struct tup_entry *tent;

	new_dt = find_dir_tupid_dt_pg(f, dt, pg, &pel, 1, full_deps);
	if(new_dt < 0)
		return -1;
	if(new_dt == 0) {
		return 0;
	}
	if(pel == NULL) {
		/* This can happen for the '.' entry */
		return 0;
	}

	if(tup_db_select_tent_part(new_dt, pel->path, pel->len, &tent) < 0)
		return -1;
	if(!tent) {
		time_t mtime = -1;
		if(full_deps && (pg->pg_flags & PG_OUTSIDE_TUP)) {
			struct stat buf;
			if(lstat(full_path, &buf) == 0) {
				mtime = buf.MTIME;
			}
			if(set_directories_to_zero(new_dt, slash_dt()) < 0)
				return -1;
		}
		/* Note that full-path entries are always ghosts since we don't scan them. They
		 * can still have a valid mtime, though.
		 */
		if(tup_db_node_insert_tent(new_dt, pel->path, pel->len, TUP_NODE_GHOST, mtime, -1, &tent) < 0) {
			fprintf(stderr, "tup error: Node '%.*s' doesn't exist in directory %lli, and no luck creating a ghost node there.\n", pel->len, pel->path, new_dt);
			return -1;
		}
	}
	free(pel);

	tup_entry_list_add(tent, head);

	return 0;
}

static int file_set_mtime(struct tup_entry *tent, const char *file)
{
	struct stat buf;
	if(fstatat(tup_top_fd(), file, &buf, AT_SYMLINK_NOFOLLOW) < 0) {
		fprintf(stderr, "tup error: file_set_mtime() fstatat failed.\n");
		perror(file);
		return -1;
	}
	if(S_ISFIFO(buf.st_mode)) {
		fprintf(stderr, "tup error: Unable to create a FIFO as an output file. They can only be used as temporary files.\n");
		return -1;
	}
	if(tup_db_set_mtime(tent, buf.MTIME) < 0)
		return -1;
	return 0;
}

static int add_config_files_locked(struct file_info *finfo, struct tup_entry *tent)
{
	struct string_tree *st;
	struct file_entry *r;
	struct tup_entry_head *entrylist;
	int full_deps = tup_option_get_int("updater.full_deps");

	entrylist = tup_entry_get_list();
	while((st = RB_ROOT(&finfo->read_root)) != NULL) {
		struct tup_entry *tmp;
		r = container_of(st, struct file_entry, filename);

		if(add_node_to_list(stderr, DOT_DT, &r->pg, entrylist, full_deps, r->filename.s) < 0)
			return -1;

		/* Don't link to ourself */
		tmp = LIST_FIRST(entrylist);
		if(tmp == tent) {
			tup_entry_list_del(tmp);
		}

		string_tree_rm(&finfo->read_root, st);
		del_entry(r, &finfo->read_root);
	}
	if(tup_db_check_config_inputs(tent, entrylist) < 0)
		return -1;
	tup_entry_release_list();

	return 0;
}

static int add_parser_files_locked(FILE *f, struct file_info *finfo,
				   struct tupid_entries *root, tupid_t vardt)
{
	struct string_tree *st;
	struct file_entry *r;
	struct mapping *map;
	struct tup_entry_head *entrylist;
	struct tup_entry *tent;
	int map_bork = 0;
	int full_deps = tup_option_get_int("updater.full_deps");

	entrylist = tup_entry_get_list();
	while((st = RB_ROOT(&finfo->read_root)) != NULL) {
		r = container_of(st, struct file_entry, filename);
		if(add_node_to_list(f, DOT_DT, &r->pg, entrylist, full_deps, r->filename.s) < 0)
			return -1;
		del_entry(r, &finfo->read_root);
	}
	while((st = RB_ROOT(&finfo->var_root)) != NULL) {
		r = container_of(st, struct file_entry, filename);
		if(add_node_to_list(f, vardt, &r->pg, entrylist, 0, NULL) < 0)
			return -1;
		del_entry(r, &finfo->var_root);
	}
	LIST_FOREACH(tent, entrylist, list) {
		if(strcmp(tent->name.s, ".gitignore") != 0)
			if(tupid_tree_add_dup(root, tent->tnode.tupid) < 0)
				return -1;
	}
	tup_entry_release_list();

	while((st = RB_ROOT(&finfo->mapping_root)) != NULL) {
		map = container_of(st, struct mapping, realname);

		if(gimme_tent(map->realname.s, &tent) < 0)
			return -1;
		if(!tent || strcmp(tent->name.s, ".gitignore") != 0) {
			fprintf(stderr, "tup error: Writing to file '%s' while parsing is not allowed. Only a .gitignore file may be created during the parsing stage.\n", map->realname.s);
			map_bork = 1;
		} else {
			if(renameat(tup_top_fd(), map->tmpname, tup_top_fd(), map->realname.s) < 0) {
				perror("renameat");
				return -1;
			}
			if(file_set_mtime(tent, map->realname.s) < 0)
				return -1;
		}
		del_mapping(map, &finfo->mapping_root);
	}
	if(map_bork)
		return -1;
	return 0;
}

static struct file_entry *new_entry(const char *filename, int len)
{
	struct file_entry *fent;

	fent = malloc(sizeof *fent);
	if(!fent) {
		perror("malloc");
		return NULL;
	}

	fent->filename.s = malloc(len+1);
	if(!fent->filename.s) {
		perror("strdup");
		free(fent);
		return NULL;
	}
	memcpy(fent->filename.s, filename, len);
	fent->filename.s[len] = 0;
	fent->filename.len = len;

	if(get_path_elements(fent->filename.s, &fent->pg) < 0) {
		free(fent->filename.s);
		free(fent);
		return NULL;
	}
	return fent;
}

static void del_entry(struct file_entry *fent, struct string_entries *root)
{
	string_tree_rm(root, &fent->filename);
	del_pel_group(&fent->pg);
	free(fent->filename.s);
	free(fent);
}

static int update_write_info(FILE *f, tupid_t cmdid, struct file_info *info,
			     int *warnings, struct tup_entry_head *entryhead)
{
	int write_bork = 0;
	struct string_tree *st;
	struct mapping *map;

	RB_FOREACH(st, string_entries, &info->mapping_root) {
		tupid_t newdt;
		struct path_element *pel = NULL;
		struct pel_group pg;

		map = container_of(st, struct mapping, realname);

		if(get_path_elements(map->realname.s, &pg) < 0) {
			return -1;
		}

		if(pg.pg_flags & PG_HIDDEN) {
			if(warnings) {
				fprintf(f, "tup warning: Writing to hidden file '%s'\n", map->realname.s);
				(*warnings)++;
			}
			continue;
		}

		newdt = find_dir_tupid_dt_pg(f, DOT_DT, &pg, &pel, 0, 0);
		if(newdt <= 0) {
			fprintf(f, "tup error: File '%s' was written to, but is not in .tup/db. You probably should specify it as an output\n", map->realname.s);
			return -1;
		}
		if(!pel) {
			fprintf(f, "[31mtup internal error: find_dir_tupid_dt_pg() in write_files() didn't get a final pel pointer.[0m\n");
			return -1;
		}

		if(tup_db_select_tent_part(newdt, pel->path, pel->len, &map->tent) < 0)
			return -1;
		free(pel);
		if(!map->tent) {
			fprintf(f, "tup error: File '%s' was written to, but is not in .tup/db. You probably should specify it as an output\n", map->realname.s);
			write_bork = 1;
		} else {
			tup_entry_list_add(map->tent, entryhead);
		}
	}

	if(write_bork) {
		while((st = RB_ROOT(&info->mapping_root)) != NULL) {
			map = container_of(st, struct mapping, realname);
			unlink(map->tmpname);
			del_mapping(map, &info->mapping_root);
		}
		return -1;
	}

	if(tup_db_check_actual_outputs(f, cmdid, entryhead) < 0)
		return -1;

	while((st = RB_ROOT(&info->mapping_root)) != NULL) {
		map = container_of(st, struct mapping, realname);

		/* TODO: strcmp only here for win32 support */
		if(strcmp(map->tmpname, map->realname.s) != 0) {
			if(renameat(tup_top_fd(), map->tmpname, tup_top_fd(), map->realname.s) < 0) {
				perror(map->realname.s);
				fprintf(f, "tup error: Unable to rename temporary file '%s' to destination '%s'\n", map->tmpname, map->realname.s);
				write_bork = 1;
			}
		}
		if(map->tent) {
			/* tent may not be set (in the case of hidden files) */
			if(file_set_mtime(map->tent, map->realname.s) < 0)
				return -1;
		}
		del_mapping(map, &info->mapping_root);
	}

	if(write_bork)
		return -1;

	return 0;
}

static int update_read_info(FILE *f, tupid_t cmdid, struct file_info *info,
			    struct tup_entry_head *entryhead,
			    struct tupid_entries *sticky_root,
			    struct tupid_entries *normal_root, int full_deps, tupid_t vardt)
{
	struct file_entry *r;
	struct string_tree *st;

	while((st = RB_ROOT(&info->read_root)) != NULL) {
		r = container_of(st, struct file_entry, filename);
		if(add_node_to_list(f, DOT_DT, &r->pg, entryhead, full_deps, r->filename.s) < 0)
			return -1;
		del_entry(r, &info->read_root);
	}

	while((st = RB_ROOT(&info->var_root)) != NULL) {
		r = container_of(st, struct file_entry, filename);
		if(add_node_to_list(f, vardt, &r->pg, entryhead, 0, NULL) < 0)
			return -1;
		del_entry(r, &info->var_root);
	}

	if(tup_db_check_actual_inputs(f, cmdid, entryhead, sticky_root, normal_root) < 0)
		return -1;
	return 0;
}
