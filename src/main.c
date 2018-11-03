#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t run_tracee(int argc, char *argv[])
{
	pid_t child = fork();

	if (child < 0) {
		fprintf(stderr, "can't fork: %s\n", strerror(errno));
		return -1;
	}

	if (child != 0)
		return child;

	if (ptrace(PTRACE_TRACEME) < 0) {
		fprintf(stderr, "prace(PTRACE_TRACEME) failed: %s\n", strerror(errno));
		return -1;
	}

	fprintf(stderr, "start program: `%s", argv[0]);
	for (int i = 1; i < argc; i++) {
		fprintf(stderr, " %s", argv[i]);
	}
	fprintf(stderr, "'\n");

	execvp(argv[0], argv);

	fprintf(stderr, "exec failed: %s\n", strerror(errno));

	return -1;
}

struct trace_context {
	uint32_t syscall;

	const char *on_enter;
	const char *on_leave;

	struct user_regs_struct regs_on_enter;
	bool in_syscall;
};

static int run_script(const char *command)
{
	if (command == NULL)
		return 0;

	int r = system(command);
	if (r < 0)
		return r;

	if (WIFEXITED(r) != 0)
		return WEXITSTATUS(r);

	return r;
}

static int on_enter(struct trace_context *ctx)
{
	return run_script(ctx->on_enter);
}

static int on_leave(struct trace_context *ctx)
{
	return run_script(ctx->on_leave);
}

#define PRIxALIGN "012"
static void syscall_dump(const struct trace_context *ctx, const struct user_regs_struct *current_regs)
{
	// man syscall(2)
	fprintf(stderr, "syscall %3llu, rdi: 0x%" PRIxALIGN "llx, rsi: 0x%" PRIxALIGN "llx, rdx: 0x%" PRIxALIGN "llx"
			", r10: 0x%" PRIxALIGN "llx, r8: 0x%" PRIxALIGN "llx, r9: 0x%" PRIxALIGN "llx = 0x%" PRIxALIGN"llx\n",
			ctx->regs_on_enter.orig_rax, ctx->regs_on_enter.rdi, ctx->regs_on_enter.rsi,
			ctx->regs_on_enter.rdx, ctx->regs_on_enter.r10, ctx->regs_on_enter.r8,
			ctx->regs_on_enter.r9, current_regs->rax);
}

static int process_event(pid_t tracee, struct trace_context *ctx)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, tracee, NULL, &regs) < 0) {
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed: %s\n", strerror(errno));
		return -1;
	}

	if (regs.orig_rax != ctx->syscall) {
		if (ctx->in_syscall == true) {
			fprintf(stderr, "unexpected event, while wait for syscall leave\n");
			return -1;
		}

		return 0;
	}

	if (ctx->in_syscall == false) {
		ctx->regs_on_enter = regs;
		ctx->in_syscall = true;

		return on_enter(ctx);
	}
	ctx->in_syscall = false;

	syscall_dump(ctx, &regs);

	return on_leave(ctx);
}

static int trace(uint32_t syscall, const char *on_enter, const char *on_leave, int argc, char *argv[])
{
	struct trace_context ctx = {
		.syscall = syscall,

		.on_enter = on_enter,
		.on_leave = on_leave,
	};

	pid_t tracee = run_tracee(argc, argv);
	if (tracee < 0)
		return -1;

	int r = 0;
	while (r == 0) {
		int status;

		if (wait(&status) < 0) {
			fprintf(stderr, "wait failed: %s\n", strerror(errno));
			r = -1;

			break;
		}
		if (WIFEXITED(status) != 0) {
			tracee = -1;
			break;
		}

		r = process_event(tracee, &ctx);
		if (r != 0)
			break;

		if (ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) < 0) {
			fprintf(stderr, "ptrace(PTRACE_SYSCALL) failed: %s\n", strerror(errno));
			r = -1;
		}
	}

	if (tracee != -1) {
		if (ptrace(PTRACE_DETACH, tracee, NULL, NULL) < 0) {
			fprintf(stderr, "can't detach: %s\n", strerror(errno));
			r = -1;
		}
	}

	return r;
}

static void cleanup_ptr(void *p)
{
	free(*(void **)p);
}

int main(int argc, char *argv[])
{
	int usage(void)
	{
		fprintf(stderr, "Usage: %s -n <syscal number> [-e <on enter script>] [-l <on leave script>] command...\n", argv[0]);
		return 1;
	}

	char *on_enter __attribute__((cleanup(cleanup_ptr))) = NULL;
	char *on_leave __attribute__((cleanup(cleanup_ptr))) = NULL;
	uint32_t syscall = -1;
	int opt;

	while ((opt = getopt(argc, argv, "e:n:l:h")) != -1) {
		switch (opt) {
		case 'n': {
			char *endptr;
			uint64_t r;

			errno = 0;
			r = strtoull(optarg, &endptr, 10);
			if (errno != 0 || r > UINT32_MAX || *endptr != '\0') {
				fprintf(stderr, "bad `syscall number' argument specified: `%s'\n", optarg);
				return usage();
			}

			syscall = r;
			break;
		}
		case 'e':
			if (on_enter != NULL)
				free(on_enter);

			on_enter = strdup(optarg);
			break;
		case 'l':
			if (on_leave != NULL)
				free(on_leave);

			on_leave = strdup(optarg);
			break;
		default:
			return usage();
		}
	}

	if (syscall == (uint32_t)-1) {
		fprintf(stderr, "`syscall number' argument was not specified\n");
		return usage();
	}

	if (optind == argc) {
		fprintf(stderr, "command to trace was not specified\n");
		return usage();
	}

	return trace(syscall, on_enter, on_leave, argc - optind, &argv[optind]);
}
