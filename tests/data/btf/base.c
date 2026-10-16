/* The "kernel" of the split-BTF fixture: types a module shares (see split.sh). */
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

int device_register(struct device *dev) { return dev->id != 0; }
