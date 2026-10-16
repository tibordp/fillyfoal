/* A "module" whose BTF is split against base.c's (see split.sh). */
typedef unsigned int u32;
typedef unsigned long long u64;

struct list_head {
	struct list_head *next, *prev;
};

struct device {
	const char *name;
	u32 id;
	struct list_head children;
};

enum widget_state { WIDGET_IDLE, WIDGET_BUSY = 4 };

struct widget {
	struct device *dev;
	struct list_head node;
	enum widget_state state;
	u64 counters[3];
	const volatile u32 *regs;
	int (*probe)(struct widget *, const char *);
};

struct widget widgets[2];

int widget_probe(struct widget *w, const char *why)
{
	return w->dev != 0 && why != 0 ? (int)w->state : 0;
}
