#	$NetBSD: Makefile,v 1.1 2019/11/11 22:45:15 joerg Exp $

LIB=	clangFrontend

.include <bsd.init.mk>

.PATH: ${CLANG_SRCDIR}/lib/Frontend

SRCS+=	ASTConsumers.cpp \
	ASTMerge.cpp \
	ASTUnit.cpp \
	ChainedDiagnosticConsumer.cpp \
	ChainedIncludesSource.cpp \
	CompilerInstance.cpp \
	CompilerInvocation.cpp \
	CreateInvocationFromCommandLine.cpp \
	DependencyFile.cpp \
	DependencyGraph.cpp \
	DiagnosticRenderer.cpp \
	FrontendAction.cpp \
	FrontendActions.cpp \
	FrontendOptions.cpp \
	FrontendTiming.cpp \
	HeaderIncludeGen.cpp \
	InitHeaderSearch.cpp \
	InitPreprocessor.cpp \
	InterfaceStubFunctionsConsumer.cpp \
	LayoutOverrideSource.cpp \
	LogDiagnosticPrinter.cpp \
	ModuleDependencyCollector.cpp \
	MultiplexConsumer.cpp \
	PrecompiledPreamble.cpp \
	PrintPreprocessedOutput.cpp \
	SerializedDiagnosticPrinter.cpp \
	SerializedDiagnosticReader.cpp \
	TestModuleFileExtension.cpp \
	TextDiagnostic.cpp \
	TextDiagnosticBuffer.cpp \
	TextDiagnosticPrinter.cpp \
	VerifyDiagnosticConsumer.cpp

.if defined(HOSTLIB)
.include <bsd.hostlib.mk>
.else
.include <bsd.lib.mk>
.endif
