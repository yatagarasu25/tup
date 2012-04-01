/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2012  Mike Shal <marfey@gmail.com>
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

#include "win_handle_map.h"
#include "tup/tupid_tree.h"
#include "tup/container.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct win_handle_map {
	struct tupid_tree tnode;
	char *path;
};

static struct tupid_entries map_root = RB_INITIALIZER(&map_root);

int add_win_handle_map(unsigned long handle, const char *path)
{
	struct win_handle_map *whm;

	del_win_handle_map(handle);

	whm = malloc(sizeof *whm);
	if(!whm) {
		perror("malloc");
		return -1;
	}
	whm->path = strdup(path);
	if(!whm->path) {
		perror("strdup");
		return -1;
	}
	whm->tnode.tupid = handle;
	if(tupid_tree_insert(&map_root, &whm->tnode) < 0)
		return -1;
	return 0;
}

static struct win_handle_map *win_handle_search(unsigned long handle)
{
	struct tupid_tree *tt;

	tt = tupid_tree_search(&map_root, handle);
	if(tt) {
		return container_of(tt, struct win_handle_map, tnode);
	}
	return NULL;
}

void del_win_handle_map(unsigned long handle)
{
	struct win_handle_map *whm;

	whm = win_handle_search(handle);
	if(whm) {
		tupid_tree_rm(&map_root, &whm->tnode);
		free(whm->path);
		free(whm);
	}
}

const char *win_handle_path(unsigned long handle)
{
	struct win_handle_map *whm;

	whm = win_handle_search(handle);
	if(whm) {
		return whm->path;
	}
	return NULL;
}
