/* A small BPF program with CO-RE relocations (see core.sh). */
#define SEC(name) __attribute__((section(name), used))
#define __core __attribute__((preserve_access_index))

struct task {
	int pid;
	struct {
		long state;
		unsigned int flags : 4;
	} sched;
	char comm[16];
} __core;

enum mode { MODE_A = 1, MODE_B = 2 };

int seen SEC(".bss");

SEC("tracepoint/sched/sched_switch")
int on_switch(struct task *t)
{
	int n = t->pid;
	n += t->comm[3];
	n += __builtin_preserve_field_info(t->sched.flags, 2);  /* FIELD_EXISTS */
	n += __builtin_preserve_field_info(t->sched.state, 1);  /* FIELD_BYTE_SIZE */
	n += __builtin_preserve_type_info(*t, 1);               /* TYPE_SIZE */
	n += __builtin_preserve_enum_value(*(enum mode *)MODE_B, 1); /* ENUMVAL_VALUE */
	seen = n;
	return 0;
}

char _license[] SEC("license") = "GPL";
