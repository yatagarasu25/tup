/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2011  Mike Shal <marfey@gmail.com>
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

#include "mapping.h"
#include "container.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mapping *add_mapping(const char *realname, const char *tmpname,
			    struct string_entries *mapping_root)
{
	struct mapping *map;

	map = malloc(sizeof *map);
	if(!map) {
		perror("malloc");
		return NULL;
	}
	map->realname.s = strdup(realname);
	if(!map->realname.s) {
		perror("strdup");
		return NULL;
	}
	map->realname.len = strlen(map->realname.s);

	map->tmpname = strdup(tmpname);
	if(!map->tmpname) {
		perror("strdup");
		return NULL;
	}
	map->tent = NULL; /* This is used when saving dependencies */

	if(string_tree_insert(mapping_root, &map->realname) < 0) {
		fprintf(stderr, "tup internal error: Unable to add map entry for '%s'\n", realname);
		return NULL;
	}

	return map;
}

void del_mapping(struct mapping *map, struct string_entries *mapping_root)
{
	string_tree_rm(mapping_root, &map->realname);
	free(map->tmpname);
	free(map->realname.s);
	free(map);
}

struct mapping *get_mapping(const char *path, struct string_entries *mapping_root)
{
	struct string_tree *st;

	st = string_tree_search(mapping_root, path, strlen(path));
	if(st) {
		return container_of(st, struct mapping, realname);
	}
	return NULL;
}
