#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mcheck.h>
#include <errno.h>
#include "tup/config.h"
#include "tup/lock.h"
#include "tup/getexecwd.h"
#include "tup/monitor.h"
#include "tup/fileio.h"
#include "tup/updater.h"
#include "tup/graph.h"

static int file_exists(const char *s);

static int init(int argc, char **argv);
static int graph_cb(void *arg, struct db_node *dbn);
static int graph(int argc, char **argv);
/* Testing commands */
static int mlink(int argc, char **argv);
static int node_exists(int argc, char **argv);
static int link_exists(int argc, char **argv);
static int flags_exists_cb(void *arg, int argc, char **argv, char **col);
static int flags_exists(int argc, char **argv);
static int get_flags_cb(void *arg, int argc, char **argv, char **col);
static int get_flags(int argc, char **argv);
static int touch(int argc, char **argv);
static int delete(int argc, char **argv);
static int varset(int argc, char **argv);

static int check_open_fds(void);
static void usage(void);

int main(int argc, char **argv)
{
	int rc = 0;
	const char *cmd;

	mtrace();
	if(argc < 2) {
		usage();
		return 1;
	}

	if(strcmp(argv[1], "init") == 0) {
		argc--;
		argv++;
		return init(argc, argv);
	}

	if(find_tup_dir() != 0) {
		return 1;
	}

	if(init_getexecwd(argv[0]) < 0) {
		fprintf(stderr, "Error: Unable to determine tup's "
			"execution directory for shared libs.\n");
		return 1;
	}

	if(tup_lock_init() < 0) {
		return 1;
	}
	if(tup_db_open() != 0) {
		rc = 1;
		goto out;
	}

	cmd = argv[1];
	argc--;
	argv++;
	if(strcmp(cmd, "monitor") == 0) {
		rc = monitor(argc, argv);
	} else if(strcmp(cmd, "stop") == 0) {
		rc = stop_monitor(argc, argv);
	} else if(strcmp(cmd, "g") == 0) {
		rc = graph(argc, argv);
	} else if(strcmp(cmd, "link") == 0) {
		rc = mlink(argc, argv);
	} else if(strcmp(cmd, "upd") == 0) {
		rc = updater(argc, argv);
	} else if(strcmp(cmd, "node_exists") == 0) {
		rc = node_exists(argc, argv);
	} else if(strcmp(cmd, "link_exists") == 0) {
		rc = link_exists(argc, argv);
	} else if(strcmp(cmd, "flags_exists") == 0) {
		rc = flags_exists(argc, argv);
	} else if(strcmp(cmd, "get_flags") == 0) {
		rc = get_flags(argc, argv);
	} else if(strcmp(cmd, "touch") == 0) {
		rc = touch(argc, argv);
	} else if(strcmp(cmd, "delete") == 0) {
		rc = delete(argc, argv);
	} else if(strcmp(cmd, "varset") == 0) {
		rc = varset(argc, argv);
	} else {
		fprintf(stderr, "Unknown tup command: %s\n", argv[0]);
		rc = 1;
	}

	tup_db_close();
out:
	tup_lock_exit();

	if(check_open_fds() < 0) {
		if(rc == 0) {
			fprintf(stderr, "Returning failure due to open FDs.\n");
			rc = 1;
		}
	}
	return rc;
}

static int file_exists(const char *s)
{
	struct stat buf;

	if(stat(s, &buf) == 0) {
		return 1;
	}
	return 0;
}

static int init(int argc, char **argv)
{
	int x;
	int db_sync = 1;

	for(x=0; x<argc; x++) {
		if(strcmp(argv[x], "--no-sync") == 0)
			db_sync = 0;
	}

	if(file_exists(TUP_DB_FILE)) {
		printf("TODO: DB file already exists. abort\n");
		return -1;
	}

	if(!file_exists(TUP_DIR)) {
		if(mkdir(TUP_DIR, 0777) != 0) {
			perror(TUP_DIR);
			return -1;
		}
	}

	if(tup_db_create(db_sync) != 0) {
		return -1;
	}

	if(creat(TUP_OBJECT_LOCK, 0666) < 0) {
		perror(TUP_OBJECT_LOCK);
		return -1;
	}
	if(creat(TUP_UPDATE_LOCK, 0666) < 0) {
		perror(TUP_UPDATE_LOCK);
		return -1;
	}
	if(creat(TUP_MONITOR_LOCK, 0666) < 0) {
		perror(TUP_MONITOR_LOCK);
		return -1;
	}
	return 0;
}

static int graph_cb(void *arg, struct db_node *dbn)
{
	struct graph *g = arg;
	struct node *n;

	if((n = find_node(g, dbn->tupid)) != NULL)
		goto edge_create;
	n = create_node(g, dbn);
	if(!n)
		return -1;

edge_create:
	if(g->cur)
		if(create_edge(g->cur, n) < 0)
			return -1;
	return 0;
}

static int graph(int argc, char **argv)
{
	int x;
	struct graph g;
	struct node *n;
	tupid_t tupid;

	if(create_graph(&g) < 0)
		return -1;

	for(x=1; x<argc; x++) {
		struct db_node dbn;

		tupid = get_dbn(argv[x], &dbn);
		if(tupid < 0) {
			fprintf(stderr, "Unable to find tupid for: '%s'\n", argv[x]);
			return -1;
		}

		if(find_node(&g, dbn.tupid) == NULL) {
			if(!create_node(&g, &dbn))
				return -1;
		}
	}

	while(!list_empty(&g.plist)) {
		g.cur = list_entry(g.plist.next, struct node, list);
		if(tup_db_select_node_by_link(graph_cb, &g, g.cur->tupid) < 0)
			return -1;
		list_move(&g.cur->list, &g.node_list);

		if(g.cur->type == TUP_NODE_DIR) {
			tupid = g.cur->tupid;
			g.cur = NULL;
			if(tup_db_select_node_dir(graph_cb, &g, tupid) < 0)
				return -1;
		}
	}

	printf("digraph G {\n");
	list_for_each_entry(n, &g.node_list, list) {
		int color;
		const char *shape;
		const char *style;
		struct edge *e;

		if(n == g.root)
			continue;

		switch(n->type) {
			case TUP_NODE_FILE:
				shape = "oval";
				break;
			case TUP_NODE_CMD:
				shape = "rectangle";
				break;
			case TUP_NODE_DIR:
				shape = "diamond";
				break;
			case TUP_NODE_VAR:
				shape = "octagon";
				break;
			default:
				shape="ellipse";
		}

		style = "solid";
		color = 0;
		if(n->flags & TUP_FLAGS_MODIFY) {
			color |= 0x0000ff;
			style = "dashed";
		} else if(n->flags & TUP_FLAGS_CREATE) {
			color |= 0x00ff00;
			style = "dashed peripheries=2";
		} else if(n->flags & TUP_FLAGS_DELETE) {
			color |= 0xff0000;
			style = "dotted";
		}
		printf("\tnode_%lli [label=\"%s\\n%lli\" shape=\"%s\" color=\"#%06x\" style=%s];\n", n->tupid, n->name, n->tupid, shape, color, style);
		if(n->dt)
			printf("\tnode_%lli -> node_%lli [dir=back color=\"#888888\"]\n", n->tupid, n->dt);

		e = n->edges;
		while(e) {
			printf("\tnode_%lli -> node_%lli [dir=back]\n", e->dest->tupid, n->tupid);
			e = e->next;
		}
	}
	printf("}\n");
	return 0;
}

static int mlink(int argc, char **argv)
{
	/* This only works for files in the top-level directory. It's only
	 * used by the benchmarking suite, and in fact may just disappear
	 * entirely. I wouldn't use it for any other purpose.
	 */
	int type;
	int x;
	tupid_t cmd_id;
	tupid_t dotdt;
	tupid_t id;

	if(argc < 4) {
		fprintf(stderr, "Usage: %s cmd -iread_file -owrite_file\n",
			argv[0]);
		return 1;
	}

	dotdt = create_dir_file(0, ".");
	if(dotdt < 0)
		return -1;

	cmd_id = create_command_file(dotdt, argv[1]);
	if(cmd_id < 0) {
		return -1;
	}

	for(x=2; x<argc; x++) {
		char *name = argv[x];
		if(name[0] == '-') {
			if(name[1] == 'i') {
				type = 0;
			} else if(name[1] == 'o') {
				type = 1;
			} else {
				fprintf(stderr, "Invalid argument: '%s'\n",
					name);
				return 1;
			}
		} else {
			fprintf(stderr, "Invalid argument: '%s'\n", name);
			return 1;
		}

		id = create_name_file(dotdt, name+2);
		if(id < 0)
			return 1;

		if(type == 0) {
			if(tup_db_create_link(id, cmd_id) < 0)
				return -1;
		} else {
			if(tup_db_create_link(cmd_id, id) < 0)
				return -1;
		}
	}

	return 0;
}

static int node_exists(int argc, char **argv)
{
	int x;
	tupid_t dt;

	if(argc < 3) {
		fprintf(stderr, "Usage: node_exists dir [n1] [n2...]\n");
		return -1;
	}
	dt = find_dir_tupid(argv[1]);
	if(dt < 0)
		return -1;
	argv++;
	argc--;
	for(x=1; x<argc; x++) {
		if(tup_db_select_node(dt, argv[x]) < 0)
			return -1;
	}
	return 0;
}

static int link_exists(int argc, char **argv)
{
	tupid_t dta, dtb;
	tupid_t a, b;

	if(argc != 5) {
		fprintf(stderr, "Error: link_exists requires two dir/name pairs.\n");
		return -1;
	}
	dta = find_dir_tupid(argv[1]);
	if(dta < 0) {
		fprintf(stderr, "Error: dir '%s' doesn't exist.\n", argv[1]);
		return -1;
	}

	a = tup_db_select_node(dta, argv[2]);
	if(a < 0) {
		fprintf(stderr, "Error: node '%s' doesn't exist.\n", argv[2]);
		return -1;
	}

	dtb = find_dir_tupid(argv[3]);
	if(dtb < 0) {
		fprintf(stderr, "Error: dir '%s' doesn't exist.\n", argv[3]);
		return -1;
	}

	b = tup_db_select_node(dtb, argv[4]);
	if(b < 0) {
		fprintf(stderr, "Error: node '%s' doesn't exist.\n", argv[4]);
		return -1;
	}
	return tup_db_link_exists(a, b);
}

static int flags_exists_cb(void *arg, int argc, char **argv, char **col)
{
	int *iptr = arg;
	if(argc) {}
	if(argv) {}
	if(col) {}

	*iptr = 1;

	return 0;
}

static int flags_exists(int argc, char **argv)
{
	int x = 0;
	if(argc) {}
	if(argv) {}

	if(tup_db_select(flags_exists_cb, &x,
			 "select id from node where flags != 0") != 0)
		return -1;
	return x;
}

static int get_flags_cb(void *arg, int argc, char **argv, char **col)
{
	int *iptr = arg;
	int x;

	for(x=0; x<argc; x++) {
		if(strcmp(col[x], "flags") == 0) {
			*iptr = atoi(argv[x]);
			return 0;
		}
	}
	return -1;
}

static int get_flags(int argc, char **argv)
{
	int flags;
	int requested_flags;

	if(argc != 3) {
		fprintf(stderr, "Error: get_flags requires exactly two args\n");
		return -1;
	}

	if(tup_db_select(get_flags_cb, &flags, "select flags from node where name='%q'", argv[1]) != 0)
		return -1;

	requested_flags = atoi(argv[2]);

	if((flags & requested_flags) != requested_flags)
		return -1;
	return 0;
}

static int touch(int argc, char **argv)
{
	int x;
	if(tup_db_begin() < 0)
		return -1;
	for(x=1; x<argc; x++) {
		if(tup_pathname_mod(argv[x], TUP_FLAGS_MODIFY) < 0)
			return -1;
	}
	if(tup_db_commit() < 0)
		return -1;
	return 0;
}

static int delete(int argc, char **argv)
{
	int x;
	for(x=1; x<argc; x++) {
		if(tup_pathname_mod(argv[x], TUP_FLAGS_DELETE) < 0)
			return -1;
	}
	return 0;
}

static int varset(int argc, char **argv)
{
	if(argc != 3) {
		fprintf(stderr, "Error: varset requires exactly two args\n");
		return -1;
	}
	if(create_var_file(argv[1], argv[2]) < 0)
		return -1;
	return 0;
}

static int check_open_fds(void)
{
	int fd;
	int flags;
	int rc = 0;

	/* This is basically from http://www.linuxquestions.org/questions/programming-9/how-to-find-out-the-number-of-open-file-descriptors-391536/, but I
	 * skip stdin/stdout/stderr/mtrace.
	 */
	for (fd = 4; fd < (int) FD_SETSIZE; fd++) {
		errno = 0;
		flags = fcntl(fd, F_GETFD, 0);
		if (flags == -1 && errno) {
			if (errno != EBADF) {
				return -1;
			}
			else
				continue;
		}
		printf("FD %i still open\n", fd);
		rc = -1;
	}
	return rc;
}

static void usage(void)
{
	printf("Usage: tup command [args]\n");
	printf("Where command is:\n");
	printf("  init		Initialize the tup database in .tup/\n");
	printf("  monitor 	Start the file monitor\n");
	printf("  stop		Stop the file monitor\n");
	printf("  g		Print a graphviz .dot graph of the .tup repository to stdout\n");
	printf("  upd		Run the updater. (Actually build stuff).\n");
}
