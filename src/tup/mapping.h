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

#ifndef tup_mapping_h
#define tup_mapping_h

#include "string_tree.h"

struct tup_entry;

struct mapping {
	struct string_tree realname;
	char *tmpname;
	struct tup_entry *tent;
};

struct mapping *add_mapping(const char *realname, const char *tmpname,
			    struct string_entries *mapping_root);
void del_mapping(struct mapping *map, struct string_entries *mapping_root);
struct mapping *get_mapping(const char *path, struct string_entries *mapping_root);

#endif
