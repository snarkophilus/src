#	$NetBSD: Makefile,v 1.7 2021/03/09 20:43:20 rillig Exp $

.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/usr.bin/indent
TESTS_SH=	t_indent

FILESDIR=	${TESTSDIR}
FILES=		binary.0
FILES+=		binary.0.stdout
FILES+=		block.0
FILES+=		block.0.stdout
FILES+=		comment-line-end.0
FILES+=		comment-line-end.0.stdout
FILES+=		comments.0
FILES+=		comments.0.pro
FILES+=		comments.0.stdout
FILES+=		declarations.0
FILES+=		declarations.0.stdout
FILES+=		elsecomment.0
FILES+=		elsecomment.0.stdout
FILES+=		elsecomment.0.pro
FILES+=		f_decls.0
FILES+=		f_decls.0.stdout
FILES+=		float.0
FILES+=		float.0.stdout
FILES+=		indent_variables.0
FILES+=		indent_variables.0.pro
FILES+=		indent_variables.0.stdout
FILES+=		label.0
FILES+=		label.0.stdout
FILES+=		label.0.pro
FILES+=		lineno.0
FILES+=		lineno.0.pro
FILES+=		lineno.0.stdout
FILES+=		list_head.0
FILES+=		list_head.0.stdout
FILES+=		ncs.0
FILES+=		ncs.0.stdout
FILES+=		ncs.0.pro
FILES+=		offsetof.0
FILES+=		offsetof.0.stdout
FILES+=		opt--version.0
FILES+=		opt--version.0.pro
FILES+=		opt--version.0.stdout
FILES+=		opt-P.0
FILES+=		opt-P.0.pro
FILES+=		opt-P.0.stdout
FILES+=		opt-T.0
FILES+=		opt-T.0.pro
FILES+=		opt-T.0.stdout
FILES+=		opt-U.0
FILES+=		opt-U.0.list
FILES+=		opt-U.0.pro
FILES+=		opt-U.0.stdout
FILES+=		opt-bacc.0
FILES+=		opt-bacc.0.pro
FILES+=		opt-bacc.0.stdout
FILES+=		opt-bad.0
FILES+=		opt-bad.0.pro
FILES+=		opt-bad.0.stdout
FILES+=		opt-badp.0
FILES+=		opt-badp.0.pro
FILES+=		opt-badp.0.stdout
FILES+=		opt-bap+sob.0
FILES+=		opt-bap+sob.0.pro
FILES+=		opt-bap+sob.0.stdout
FILES+=		opt-bap.0
FILES+=		opt-bap.0.pro
FILES+=		opt-bap.0.stdout
FILES+=		opt-bbb.0
FILES+=		opt-bbb.0.pro
FILES+=		opt-bbb.0.stdout
FILES+=		opt-bc.0
FILES+=		opt-bc.0.pro
FILES+=		opt-bc.0.stdout
FILES+=		opt-bl.0
FILES+=		opt-bl.0.pro
FILES+=		opt-bl.0.stdout
FILES+=		opt-br.0
FILES+=		opt-br.0.pro
FILES+=		opt-br.0.stdout
FILES+=		opt-bs.0
FILES+=		opt-bs.0.pro
FILES+=		opt-bs.0.stdout
FILES+=		opt-c.0
FILES+=		opt-c.0.pro
FILES+=		opt-c.0.stdout
FILES+=		opt-cd.0
FILES+=		opt-cd.0.pro
FILES+=		opt-cd.0.stdout
FILES+=		opt-cdb.0
FILES+=		opt-cdb.0.pro
FILES+=		opt-cdb.0.stdout
FILES+=		opt-ce.0
FILES+=		opt-ce.0.pro
FILES+=		opt-ce.0.stdout
FILES+=		opt-ci.0
FILES+=		opt-ci.0.pro
FILES+=		opt-ci.0.stdout
FILES+=		opt-cli.0
FILES+=		opt-cli.0.pro
FILES+=		opt-cli.0.stdout
FILES+=		opt-cs.0
FILES+=		opt-cs.0.pro
FILES+=		opt-cs.0.stdout
FILES+=		opt-d.0
FILES+=		opt-d.0.pro
FILES+=		opt-d.0.stdout
FILES+=		opt-di.0
FILES+=		opt-di.0.pro
FILES+=		opt-di.0.stdout
FILES+=		opt-dj.0
FILES+=		opt-dj.0.pro
FILES+=		opt-dj.0.stdout
FILES+=		opt-eei.0
FILES+=		opt-eei.0.pro
FILES+=		opt-eei.0.stdout
FILES+=		opt-ei.0
FILES+=		opt-ei.0.pro
FILES+=		opt-ei.0.stdout
FILES+=		opt-fbs.0
FILES+=		opt-fbs.0.pro
FILES+=		opt-fbs.0.stdout
FILES+=		opt-fc1.0
FILES+=		opt-fc1.0.pro
FILES+=		opt-fc1.0.stdout
FILES+=		opt-fcb.0
FILES+=		opt-fcb.0.pro
FILES+=		opt-fcb.0.stdout
FILES+=		opt-i.0
FILES+=		opt-i.0.pro
FILES+=		opt-i.0.stdout
FILES+=		opt-ip.0
FILES+=		opt-ip.0.pro
FILES+=		opt-ip.0.stdout
FILES+=		opt-l.0
FILES+=		opt-l.0.pro
FILES+=		opt-l.0.stdout
FILES+=		opt-lc.0
FILES+=		opt-lc.0.pro
FILES+=		opt-lc.0.stdout
FILES+=		opt-ldi.0
FILES+=		opt-ldi.0.pro
FILES+=		opt-ldi.0.stdout
FILES+=		opt-lp.0
FILES+=		opt-lp.0.pro
FILES+=		opt-lp.0.stdout
FILES+=		opt-lpl.0
FILES+=		opt-lpl.0.pro
FILES+=		opt-lpl.0.stdout
FILES+=		opt-nbacc.0
FILES+=		opt-nbacc.0.pro
FILES+=		opt-nbacc.0.stdout
FILES+=		opt-nbad.0
FILES+=		opt-nbad.0.pro
FILES+=		opt-nbad.0.stdout
FILES+=		opt-nbadp.0
FILES+=		opt-nbadp.0.pro
FILES+=		opt-nbadp.0.stdout
FILES+=		opt-nbap.0
FILES+=		opt-nbap.0.pro
FILES+=		opt-nbap.0.stdout
FILES+=		opt-nbbb.0
FILES+=		opt-nbbb.0.pro
FILES+=		opt-nbbb.0.stdout
FILES+=		opt-nbc.0
FILES+=		opt-nbc.0.pro
FILES+=		opt-nbc.0.stdout
FILES+=		opt-nbs.0
FILES+=		opt-nbs.0.pro
FILES+=		opt-nbs.0.stdout
FILES+=		opt-ncdb.0
FILES+=		opt-ncdb.0.pro
FILES+=		opt-ncdb.0.stdout
FILES+=		opt-nce.0
FILES+=		opt-nce.0.pro
FILES+=		opt-nce.0.stdout
FILES+=		opt-ncs.0
FILES+=		opt-ncs.0.pro
FILES+=		opt-ncs.0.stdout
FILES+=		opt-ndj.0
FILES+=		opt-ndj.0.pro
FILES+=		opt-ndj.0.stdout
FILES+=		opt-neei.0
FILES+=		opt-neei.0.pro
FILES+=		opt-neei.0.stdout
FILES+=		opt-nei.0
FILES+=		opt-nei.0.pro
FILES+=		opt-nei.0.stdout
FILES+=		opt-nfbs.0
FILES+=		opt-nfbs.0.pro
FILES+=		opt-nfbs.0.stdout
FILES+=		opt-nfc1.0
FILES+=		opt-nfc1.0.pro
FILES+=		opt-nfc1.0.stdout
FILES+=		opt-nfcb.0
FILES+=		opt-nfcb.0.pro
FILES+=		opt-nfcb.0.stdout
FILES+=		opt-nip.0
FILES+=		opt-nip.0.pro
FILES+=		opt-nip.0.stdout
FILES+=		opt-nlp.0
FILES+=		opt-nlp.0.pro
FILES+=		opt-nlp.0.stdout
FILES+=		opt-nlpl.0
FILES+=		opt-nlpl.0.pro
FILES+=		opt-nlpl.0.stdout
FILES+=		opt-npcs.0
FILES+=		opt-npcs.0.pro
FILES+=		opt-npcs.0.stdout
FILES+=		opt-npro.0
FILES+=		opt-npro.0.pro
FILES+=		opt-npro.0.stdout
FILES+=		opt-npsl.0
FILES+=		opt-npsl.0.pro
FILES+=		opt-npsl.0.stdout
FILES+=		opt-nsc.0
FILES+=		opt-nsc.0.pro
FILES+=		opt-nsc.0.stdout
FILES+=		opt-nsob.0
FILES+=		opt-nsob.0.pro
FILES+=		opt-nsob.0.stdout
FILES+=		opt-nut.0
FILES+=		opt-nut.0.pro
FILES+=		opt-nut.0.stdout
FILES+=		opt-nv.0
FILES+=		opt-nv.0.pro
FILES+=		opt-nv.0.stdout
FILES+=		opt-pcs.0
FILES+=		opt-pcs.0.pro
FILES+=		opt-pcs.0.stdout
FILES+=		opt-psl.0
FILES+=		opt-psl.0.pro
FILES+=		opt-psl.0.stdout
FILES+=		opt-sc.0
FILES+=		opt-sc.0.pro
FILES+=		opt-sc.0.stdout
FILES+=		opt-sob.0
FILES+=		opt-sob.0.pro
FILES+=		opt-sob.0.stdout
FILES+=		opt-ta.0
FILES+=		opt-ta.0.pro
FILES+=		opt-ta.0.stdout
FILES+=		opt-ts.0
FILES+=		opt-ts.0.pro
FILES+=		opt-ts.0.stdout
FILES+=		opt-ut.0
FILES+=		opt-ut.0.pro
FILES+=		opt-ut.0.stdout
FILES+=		opt-v.0
FILES+=		opt-v.0.pro
FILES+=		opt-v.0.stdout
FILES+=		parens.0
FILES+=		parens.0.stdout
FILES+=		parens.0.pro
FILES+=		pcs.0
FILES+=		pcs.0.stdout
FILES+=		pcs.0.pro
FILES+=		cs.0
FILES+=		cs.0.stdout
FILES+=		cs.0.pro
FILES+=		struct.0
FILES+=		struct.0.stdout
FILES+=		surplusbad.0
FILES+=		surplusbad.0.stdout
FILES+=		surplusbad.0.pro
FILES+=		types_from_file.0
FILES+=		types_from_file.0.stdout
FILES+=		types_from_file.0.list
FILES+=		types_from_file.0.pro
FILES+=		wchar.0
FILES+=		wchar.0.stdout

add-test: .PHONY
	@set -eu; \
	test=${NAME:Q}; \
	[ "$$test" ] || { \
		echo "usage: ${MAKE} add-test NAME=<name>"; \
		exit; \
	}; \
	\
	if [ -f "$$test" ]; then \
		echo "error: test $$test already exists." 1>&2; \
		exit 1; \
	fi; \
	\
	echo "=> Adding test $$test"; \
	printf '%s\n' \
		'/* $$''NetBSD$$ */' \
		'/* $$''FreeBSD$$ */' \
		'' \
		'/*' \
		' * TODO: Explain the purpose of the test.' \
		'*/' \
		'' \
		'// TODO: Add some code that passes.' \
	> "$$test"; \
	printf '%s\n' \
		'/* $$''NetBSD$$ */' \
		'/* $$''FreeBSD$$ */' \
		'' \
		'/*' \
		' * TODO: Explain the command line options of the test.' \
		' */' \
		'' \
		'/* TODO: Add some command line options */' \
	> "$$test.pro"; \
	cat < "$$test" > "$$test.stdout"; \
	cvs add "$$test" "$$test.pro" "$$test.stdout"; \
	printf '%s\n' \
		'/^FILES+=/i' \
		"FILES+=		$$test" \
		"FILES+=		$$test.pro" \
		"FILES+=		$$test.stdout" \
		'.' 'w' 'q' \
	| ed Makefile; \
	${MAKE} sync-mi

# Note: only works for adding tests.
# To remove a test, the $$mi file must be edited manually.
sync-mi: .PHONY
	@set -eu;							\
	cd "${MAKEFILE:tA:H}/../../..";					\
	mi="distrib/sets/lists/tests/mi";				\
	cvs update "$$mi";						\
	fmt="./usr/tests/usr.bin/indent/%s\ttests-usr.bin-tests\tcompattestfile,atf\n"; \
	cat "$$mi" > "$$mi.tmp";					\
	printf "$$fmt" ${FILES:M${NAME}*} >> "$$mi.tmp";		\
	distrib/sets/fmt-list "$$mi.tmp";				\
	mv "$$mi.tmp" "$$mi";						\
	cvs diff "$$mi" || true

.include <bsd.test.mk>
