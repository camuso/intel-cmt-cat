/*
 * BSD LICENSE
 *
 * Copyright(c) 2026 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Unit tests for safe_fopen() in pqos/common.c
 *
 * These tests exercise the O_NOFOLLOW symlink rejection and verify
 * that safe_fopen() preserves fopen()-compatible permissions (0666
 * modified by umask).
 */

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* clang-format off */
#include <cmocka.h>
/* clang-format on */

/*
 * Stub for pqos_get_num_mem_regions() — only needed to satisfy the
 * linker when common.o is pulled in; never called by safe_fopen().
 */
int
pqos_get_num_mem_regions(unsigned *num_mem_regions)
{
        if (num_mem_regions != NULL)
                *num_mem_regions = 0;
        return 0;
}

#define TEST_DIR     "/tmp/test_safe_fopen_XXXXXX"
#define TEST_FILE    "testfile"
#define TARGET_FILE  "target"
#define SYMLINK_NAME "symlink"

struct test_ctx {
        char dir[256];
        char filepath[512];
        char targetpath[512];
        char symlinkpath[512];
        char subdir[512];
        char subfile[512];
        char dirlink[512];
};

static int
test_setup(void **state)
{
        struct test_ctx *ctx = calloc(1, sizeof(*ctx));

        assert_non_null(ctx);

        strncpy(ctx->dir, TEST_DIR, sizeof(ctx->dir) - 1);
        assert_non_null(mkdtemp(ctx->dir));

        snprintf(ctx->filepath, sizeof(ctx->filepath), "%s/%s", ctx->dir,
                 TEST_FILE);
        snprintf(ctx->targetpath, sizeof(ctx->targetpath), "%s/%s", ctx->dir,
                 TARGET_FILE);
        snprintf(ctx->symlinkpath, sizeof(ctx->symlinkpath), "%s/%s", ctx->dir,
                 SYMLINK_NAME);
        snprintf(ctx->subdir, sizeof(ctx->subdir), "%s/realdir", ctx->dir);
        snprintf(ctx->subfile, sizeof(ctx->subfile), "%s/realdir/target",
                 ctx->dir);
        snprintf(ctx->dirlink, sizeof(ctx->dirlink), "%s/link", ctx->dir);

        *state = ctx;
        return 0;
}

static int
test_teardown(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;

        if (ctx != NULL) {
                unlink(ctx->filepath);
                unlink(ctx->targetpath);
                unlink(ctx->symlinkpath);
                unlink(ctx->subfile);
                unlink(ctx->dirlink);
                rmdir(ctx->subdir);
                rmdir(ctx->dir);
                free(ctx);
        }

        return 0;
}

/* safe_fopen returns NULL for NULL name */
static void
test_safe_fopen_null_name(void **state)
{
        FILE *fp = safe_fopen(NULL, "r");

        assert_null(fp);
        (void)state;
}

/* safe_fopen returns NULL for NULL mode */
static void
test_safe_fopen_null_mode(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;

        FILE *fp = safe_fopen(ctx->filepath, NULL);

        assert_null(fp);
}

/* safe_fopen returns NULL for unrecognised mode string */
static void
test_safe_fopen_invalid_mode(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;

        FILE *fp = safe_fopen(ctx->filepath, "x");

        assert_null(fp);
}

/* safe_fopen("w") creates a regular file and the stream is writable */
static void
test_safe_fopen_write_creates_file(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        struct stat st;

        fp = safe_fopen(ctx->filepath, "w");
        assert_non_null(fp);

        assert_true(fputs("hello\n", fp) >= 0);
        fclose(fp);

        assert_int_equal(stat(ctx->filepath, &st), 0);
        assert_true(S_ISREG(st.st_mode));
        assert_true(st.st_size > 0);
}

/* safe_fopen("r") can read back what was written */
static void
test_safe_fopen_read_existing(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        char buf[64];

        fp = safe_fopen(ctx->filepath, "w");
        assert_non_null(fp);
        fputs("data", fp);
        fclose(fp);

        fp = safe_fopen(ctx->filepath, "r");
        assert_non_null(fp);
        assert_non_null(fgets(buf, sizeof(buf), fp));
        assert_string_equal(buf, "data");
        fclose(fp);
}

/* safe_fopen rejects a symlink — the target must NOT be truncated */
static void
test_safe_fopen_rejects_symlink(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        struct stat st;
        const char *payload = "precious data\n";

        /* Create a target file with content */
        fp = fopen(ctx->targetpath, "w");
        assert_non_null(fp);
        fputs(payload, fp);
        fclose(fp);

        /* Create a symlink pointing at the target */
        assert_int_equal(symlink(ctx->targetpath, ctx->symlinkpath), 0);

        /* safe_fopen("w+") through the symlink must fail */
        fp = safe_fopen(ctx->symlinkpath, "w+");
        assert_null(fp);

        /* The target file must be untouched */
        assert_int_equal(stat(ctx->targetpath, &st), 0);
        assert_true(st.st_size == (off_t)strlen(payload));
}

/*
 * Newly created files get permissions 0666 & ~umask, matching fopen()
 * behaviour.  We temporarily force umask to 0022 so the expected
 * result is 0644.
 */
static void
test_safe_fopen_permissions(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        struct stat st;
        mode_t old_umask;

        old_umask = umask(0022);

        fp = safe_fopen(ctx->filepath, "w");
        assert_non_null(fp);
        fclose(fp);

        assert_int_equal(stat(ctx->filepath, &st), 0);
        assert_int_equal(st.st_mode & 0777, 0644);

        umask(old_umask);
}

/* safe_fopen("a") appends without truncating */
static void
test_safe_fopen_append(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        struct stat st;

        fp = safe_fopen(ctx->filepath, "w");
        assert_non_null(fp);
        fputs("first", fp);
        fclose(fp);

        fp = safe_fopen(ctx->filepath, "a");
        assert_non_null(fp);
        fputs("second", fp);
        fclose(fp);

        assert_int_equal(stat(ctx->filepath, &st), 0);
        assert_true(st.st_size == (off_t)(strlen("first") + strlen("second")));
}

/*
 * safe_fopen rejects a symlink in an intermediate path component.
 * Build: realdir/target (regular file with content)
 *        link -> realdir (symlink to directory)
 * Then open "link/target" — must fail, target untouched.
 */
static void
test_safe_fopen_rejects_intermediate_symlink(void **state)
{
        struct test_ctx *ctx = (struct test_ctx *)*state;
        FILE *fp;
        struct stat st;
        const char *payload = "important data\n";
        char via_link[1024];

        /* Create a real subdirectory with a file */
        assert_int_equal(mkdir(ctx->subdir, 0755), 0);

        fp = fopen(ctx->subfile, "w");
        assert_non_null(fp);
        fputs(payload, fp);
        fclose(fp);

        /* Create a directory symlink: dir/link -> dir/realdir */
        assert_int_equal(symlink(ctx->subdir, ctx->dirlink), 0);

        /* Try to open the file through the symlinked directory */
        snprintf(via_link, sizeof(via_link), "%s/target", ctx->dirlink);
        fp = safe_fopen(via_link, "r");
        assert_null(fp);

        /* Target file must be untouched */
        assert_int_equal(stat(ctx->subfile, &st), 0);
        assert_true(st.st_size == (off_t)strlen(payload));
}

int
main(void)
{
        const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_safe_fopen_null_name,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_null_mode,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_invalid_mode,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_write_creates_file,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_read_existing,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_rejects_symlink,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_permissions,
                                            test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(test_safe_fopen_append, test_setup,
                                            test_teardown),
            cmocka_unit_test_setup_teardown(
                test_safe_fopen_rejects_intermediate_symlink, test_setup,
                test_teardown),
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
}
