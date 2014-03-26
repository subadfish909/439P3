#include "threads/palloc.h"

struct frame
{
	char * page;
};

bool
frame_init(struct frame * f)
{
	struct frame fr = *f;
	f.page = (char *)palloc_get_page(PAL_USER);
}