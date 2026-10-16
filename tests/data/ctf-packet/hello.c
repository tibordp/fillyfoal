#include <lttng/tracef.h>

int main(void)
{
	for (int i = 0; i < 150; i++)
		lttng_ust_tracef("fillyfoal message %d", i);
	return 0;
}
