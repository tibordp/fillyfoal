/* A small BPF object whose BTF uses every type kind (see make.sh). */
#define __tag(x) __attribute__((btf_decl_tag(x)))
#define __ttag(x) __attribute__((btf_type_tag(x)))
#define SEC(name) __attribute__((section(name), used))

typedef unsigned int u32;
typedef unsigned long long u64;

struct opaque; /* FWD */

enum colour { RED, GREEN = 5, BLUE = -1 };
enum big { SMALL = 1, HUGE = 0x123456789abcULL };

struct flags {
	u32 a : 3;
	u32 b : 13;
	u32 c;
	signed char d : 2;
};

union either {
	int i;
	float f;
	double d;
	long double ld;
};

struct record {
	const char *name;
	volatile int counter;
	int *restrict scratch;
	int __ttag("user") *uptr;
	struct opaque *hidden;
	struct flags fl;
	union either value;
	enum colour colour;
	enum big big;
	_Bool ok;
	u64 history[4][2];
	int (*callback)(int, const void *);
	struct record *next;
} __tag("tagged_struct");

struct record table[2] SEC(".data.tables");
int counter_var SEC(".bss");
const volatile u32 config SEC(".rodata") = 7;

__tag("tagged_func") int __attribute__((noinline))
step(struct record *r __tag("arg_tag"), int by)
{
	r->counter += by;
	return r->colour == RED ? by : -by;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle(void *ctx)
{
	counter_var += step(&table[0], 1);
	return config;
}

char _license[] SEC("license") = "GPL";
