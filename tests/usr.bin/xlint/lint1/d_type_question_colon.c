/*	$NetBSD: d_type_question_colon.c,v 1.3 2021/01/31 14:57:28 rillig Exp $	*/
# 3 "d_type_question_colon.c"

/* the type of the ?: expression should be the more specific type */

struct foo {
	int bar;
};

void
test(void)
{
	int i;
	struct foo *ptr = 0;

	for (i = (ptr ? ptr : (void *)0)->bar; i < 10; i++)
		test();
}
