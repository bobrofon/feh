/* archive.c

Copyright (C) 2022 Sergey Bobrenok.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "archive.h"

#include <string.h>

#define FEH_ARCHIVE_URI_SCHEME "archive://"
#define FEH_ARCHIVE_URI_SCHEME_SIZE 10
#define FEH_ARCHIVE_URI_SEPARATOR ":"

bool feh_archive_is_uri(const char *path)
{
	return strncmp(path, FEH_ARCHIVE_URI_SCHEME, FEH_ARCHIVE_URI_SCHEME_SIZE) == 0;
}

#ifdef HAVE_LIBARCHIVE

#include "feh.h"
#include "options.h"
#include "utils.h"

#include <errno.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>

#define FEH_ARCHIVE_READ_BLOCK_SIZE 4096
// Some of libarchive operations may be retried after fail.
// Total amount of tries will be 1 (initial fail) + RETRY_COUNT.
#define FEH_ARCHIVE_RETRY_COUNT 2

/**
 * {name}_cb_t - type of some feh_archive_* function/interface.
 * {name}_cb - function which can be passed to another function as a callback of
 *	 type {some}_cb_t. It works as a wrapper for function {name} and makes all
 *	 kinds of conversions of input and output parameters.
 * {name}_cb_args - structure that holds additional input/output arguments of
 *	 {name} function. It may be passed to a {name}_cb function as an argument of
 *	 type void*.
 *
 * {name}_op* - the same as {name}_cb* but for archive_* functions.
 */

// Should return false to stop iteration through entries or true to continue iteration.
typedef bool (feh_archive_foreach_entry_cb_t)(struct archive_entry *e, void *data);
// Common interface for all libarchive functions.
typedef int (feh_archive_op_t)(struct archive *a, void *data);

struct feh_archive_call_uri_cb_args
{
	feh_archive_uri_cb_t *callback;
	const char *archive_path;
};
static bool feh_archive_call_uri_cb(struct archive_entry *e, void *data);

struct feh_archive_select_entry_cb_args
{
	const char *entry_path;
	struct archive_entry *entry;
};
static bool feh_archive_select_entry_cb(struct archive_entry *e, void *data);

struct feh_archive_read_next_header_op_args
{
	struct archive_entry *entry;
};
static int feh_archive_read_next_header_op(struct archive *a, void *data);

struct feh_archive_read_data_into_fd_op_args
{
	int fd;
};
static int feh_archive_read_data_into_fd_op(struct archive *a, void *data);

/**
 * Static functions declarations. Listed in the same order they appears in the file.
 */

static struct archive *feh_archive_open(const char *path, bool fail_expected);
static void feh_archive_free(struct archive *a, const char *path);
static void feh_archive_set_supported_formats(struct archive *a);
static void feh_archive_foreach_archive_uri(struct archive *a, const char *path,
	feh_archive_uri_cb_t callback);
static void feh_archive_call_uri(struct archive_entry *e, feh_archive_uri_cb_t *callback,
	const char *archive_path);
static char *feh_archive_uri(const char* archive_path, const char* entry_path);
static void feh_archive_foreach_entry(struct archive *a, const char *path, bool fail_expected,
	feh_archive_foreach_entry_cb_t callback, void *data);
static bool feh_archive_match_uri(char *uri, char **archive_path, char **entry_path);
static bool feh_archive_extract_path(const char *archive_path, const char *entry_path, int fd);
static bool feh_archive_extract_entry_path(struct archive *a, const char *archive_path,
	const char *entry_path, int fd);
static struct archive_entry *feh_archive_find_entry(struct archive *a,
	const char *archive_path, const char *entry_path);
static struct archive_entry *feh_archive_select_entry(struct archive_entry *e,
	const char *entry_path);
static bool feh_archive_eval(struct archive *a, const char *path, bool fail_expected,
	feh_archive_op_t *op, void *data);
static struct archive_entry *feh_archive_read_next_header(struct archive *a,
	const char *archive_path, bool fail_expected);
static bool feh_archive_read_data_into_fd(struct archive *a, const char *archive_path, int fd);

bool feh_archive_is_supported(const char *path, const struct stat *st)
{
	// libarchive treats empty files as archives of "empty" format. We don't
	// want to inherit this behavior, so we need to check file size explicitly.
	if (!S_ISREG(st->st_mode) || st->st_size == 0) {
		return false;
	}

	struct archive *a = feh_archive_open(path, /* fail_expected */ true);
	if (a == NULL) {
		return false;
	}
	feh_archive_free(a, path);
	return true;
}

/**
 * Return valid opened archive object or NULL in case of any error.
 * The caller is responsible for calling feh_archive_free on the result object.
 */
static struct archive *feh_archive_open(const char *path, bool fail_expected)
{
	struct archive *a = archive_read_new();
	if (a == NULL) {
		eprintf("failed to create reader for '%s' archive", path);
		return NULL;
	}
	feh_archive_set_supported_formats(a);

	int ret = archive_read_open_filename(a, path, FEH_ARCHIVE_READ_BLOCK_SIZE);
	if (ret == ARCHIVE_OK) {
		return a;
	}

	if (!fail_expected && !opt.quiet) {
		weprintf("failed to open '%s' as an archive: %s\n", path, archive_error_string(a));
	}
	return NULL;
}

/**
 * Closes an archive and frees all resources associated with it.
 */
static void feh_archive_free(struct archive *a, const char *path)
{
	int ret = archive_read_free(a); // implicitly closes the archive
	if (ret != ARCHIVE_OK) {
		weprintf("failed to free archive '%s': %s\n", path, archive_error_string(a));
	}
}

static void feh_archive_set_supported_formats(struct archive *a)
{
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a); // includes "empty" format
}

void feh_archive_foreach_uri(const char *path, feh_archive_uri_cb_t callback)
{
	struct archive *a = feh_archive_open(path, /* fail_expected */ false);
	if (a == NULL) {
		if (!opt.quiet) {
			weprintf("failed to open '%s' - skipping", path);
		}
		return;
	}
	feh_archive_foreach_archive_uri(a, path, callback);
	feh_archive_free(a, path);
}

static void feh_archive_foreach_archive_uri(struct archive *a, const char *path,
	feh_archive_uri_cb_t callback)
{
	struct feh_archive_call_uri_cb_args args = {
		.callback = callback,
		.archive_path = path,
	};
	feh_archive_foreach_entry(a, path, /* fail_expected */ true,
		feh_archive_call_uri_cb, &args);
}

static bool feh_archive_call_uri_cb(struct archive_entry *e, void *data)
{
	struct feh_archive_call_uri_cb_args *args = data;
	feh_archive_call_uri(e, args->callback, args->archive_path);
	return true; // continue
}

static void feh_archive_call_uri(struct archive_entry *e, feh_archive_uri_cb_t *callback,
	const char *archive_path)
{
	const char *entry_path = archive_entry_pathname(e);
	if (entry_path == NULL) {
		// most of the time it happens because of problems with character encoding
		if (!opt.quiet) {
			weprintf("failed to read archive entry path - skipping");
		}
		return;
	}

	mode_t entry_type = archive_entry_filetype(e);
	if (entry_type != AE_IFREG) {
		D(("'%s' is not a regular file (type = %d) - skipping", entry_path, (int)entry_type));
		return;
	}

	char *uri = feh_archive_uri(archive_path, entry_path);
	callback(uri);
	free(uri);
}

/**
 * Creates an archive URI based on archive and entry paths.
 * It is the caller's responsibility to free the result URI string.
 */
static char *feh_archive_uri(const char* archive_path, const char* entry_path)
{
	// this implementation should be in sync with feh_archive_is_uri
	return estrjoin("", FEH_ARCHIVE_URI_SCHEME, archive_path, FEH_ARCHIVE_URI_SEPARATOR,
		entry_path, NULL);
}

static void feh_archive_foreach_entry(struct archive *a, const char *path, bool fail_expected,
	feh_archive_foreach_entry_cb_t callback, void *data)
{
	struct archive_entry *entry = NULL;
	while ((entry = feh_archive_read_next_header(a, path, fail_expected)) != NULL) {
		if (!callback(entry, data)) {
			return;
		}
	}
}

/**
 * Reads next archive entry header.
 * Gracefully handles libarchive errors.
 * Returns result archive entry in case of success or NULL.
 */
static struct archive_entry *feh_archive_read_next_header(struct archive *a,
	const char *path, bool fail_expected)
{
	struct feh_archive_read_next_header_op_args args = {
		.entry = NULL, // output parameter
	};
	if (feh_archive_eval(a, path, fail_expected, feh_archive_read_next_header_op, &args)) {
		return args.entry;
	}
	return NULL;
}

bool feh_archive_extract_uri(/* const */ char *uri, int fd)
{
	char *uri_copy = estrdup(uri);
	if (uri_copy == NULL) {
		return false;
	}

	bool extracted = false;
	char *archive_path = NULL;
	char *entry_path = NULL;
	if (!feh_archive_match_uri(uri_copy, &archive_path, &entry_path)) {
		weprintf("failed to match archive uri '%s' to local file", uri_copy);
		extracted = false;
		goto exit;
	}
	D(("extracting '%s' from '%s'\n", entry_path, archive_path));
	extracted = feh_archive_extract_path(archive_path, entry_path, fd);

exit:
	free(uri_copy);
	return extracted;
}

/**
 * Tries to split an archive URI into archive and entry paths. Ensures that the
 * archive path exists. Returns true in case of success.
 * 'uri' MUST be a valid archive uri.
 */
static bool feh_archive_match_uri(char *uri, char **archive_path, char **entry_path)
{
	*archive_path = uri + FEH_ARCHIVE_URI_SCHEME_SIZE;
	*entry_path = *archive_path;

	while (**entry_path != '\0') {
		*entry_path = strchr(*entry_path, *FEH_ARCHIVE_URI_SEPARATOR);
		if (*entry_path == NULL) {
			return false;
		}

		// URI may contain multiple separators, so we need to check if the archive exists
		**entry_path = '\0';
		if (access(*archive_path, F_OK) == 0) {
			++*entry_path;
			return true;
		}
		if (errno != ENOENT) {
			weprintf("cannot check archive path '%s':", *archive_path);
			**entry_path = *FEH_ARCHIVE_URI_SEPARATOR;
			return false;
		}

		**entry_path = *FEH_ARCHIVE_URI_SEPARATOR;
		++*entry_path;
		D(("retrying to find archive path delimiter in '%s'\n", *entry_path));
	}

	return false;
}

static bool feh_archive_extract_path(const char *archive_path, const char *entry_path, int fd)
{
	struct archive *a = feh_archive_open(archive_path, /* fail_expected */ false);
	if (a == NULL) {
		return false;
	}

	bool extracted = feh_archive_extract_entry_path(a, archive_path, entry_path, fd);

	feh_archive_free(a, archive_path);
	return extracted;
}

static bool feh_archive_extract_entry_path(struct archive *a, const char *archive_path,
	const char *entry_path, int fd)
{
	struct archive_entry *e = feh_archive_find_entry(a, archive_path, entry_path);
	if (e == NULL) {
		weprintf("failed to find '%s' in archive '%s'", entry_path, archive_path);
		return false;
	}
	D(("found archive entry '%s'\n", entry_path));

	if (!feh_archive_read_data_into_fd(a, archive_path, fd)) {
		weprintf("failed to extract archive entry '%s'('%s'): %s\n", archive_path, entry_path,
			archive_error_string(a));
		return false;
	}

	return true;
}

/**
 * Reads current archive entry's content into a file descriptor.
 * Gracefully handles libarchive errors.
 * Returns true in case of success.
 */
static bool feh_archive_read_data_into_fd(struct archive *a, const char *archive_path, int fd)
{
	struct feh_archive_read_data_into_fd_op_args args = {
		.fd = fd,
	};
	return feh_archive_eval(a, archive_path, /* fail_expected */ false,
		feh_archive_read_data_into_fd_op, &args);
}

/**
 * Reads the archive until current entry's pathname equals entry_path.
 * Returns current entry if such entry was found or NULL.
 */
static struct archive_entry *feh_archive_find_entry(struct archive *a,
	const char *archive_path, const char *entry_path)
{
	struct feh_archive_select_entry_cb_args args = {
		.entry_path = entry_path,
		.entry = NULL,
	};
	feh_archive_foreach_entry(a, archive_path, /* fail_expected */ false,
		feh_archive_select_entry_cb, &args);
	return args.entry;
}

static bool feh_archive_select_entry_cb(struct archive_entry *e, void *data)
{
	struct feh_archive_select_entry_cb_args *args = data;
	args->entry = feh_archive_select_entry(e, args->entry_path);
	return args->entry == NULL; // stop searching if already found
}

/**
 * Returns the same archive_entry if it has a given pathname or NULL instead.
 */
static struct archive_entry *feh_archive_select_entry(struct archive_entry *e,
	const char *entry_path)
{
	const char *path = archive_entry_pathname(e);
	if (path == NULL) {
		D(("failed to read archive entry path - skipping\n"));
		return NULL;
	}

	if (strcmp(path, entry_path) != 0) {
		return NULL;
	}
	return e;
}

/**
 * Tries to call a provided libarchive operation and gracefully handle its
 * result. Can retry some operations. Returns true if the operation was
 * successful (maybe with retries or warnings).
 */
static bool feh_archive_eval(struct archive *a, const char *path, bool fail_expected,
	feh_archive_op_t *op, void *data)
{
	for (unsigned int retries = 0; retries <= FEH_ARCHIVE_RETRY_COUNT;) {
		int ret = op(a, data);
		switch (ret) {
		case ARCHIVE_WARN:
			// the operation succeeded but a non-critical error was encountered
			if (!fail_expected || !opt.quiet) {
				weprintf("'%s': %s - skipping the rest of the archive", path,
					archive_error_string(a));
			}
			// fallthrough
		case ARCHIVE_OK:
			return true;
		case ARCHIVE_RETRY:
			// the operation failed but can be retried
			++retries;
			if ((!fail_expected || !opt.quiet) && retries <= FEH_ARCHIVE_RETRY_COUNT) {
				weprintf("'%s': %s - retrying [%u/%u]", path, archive_error_string(a), retries,
					FEH_ARCHIVE_RETRY_COUNT);
			} else if (!fail_expected || !opt.quiet) {
				weprintf("'%s': %s - skipping the rest of the archive", path,
					archive_error_string(a));
			}
			return false;
		case ARCHIVE_FATAL:
			//there was a fatal error; the archive should be closed immediately
			if (!fail_expected || !opt.quiet) {
				weprintf("'%s': %s - skipping the rest of the archive", path,
					archive_error_string(a));
			}
			return false;
		case ARCHIVE_EOF:
			// end-of-archive was encountered
			return false;
		default:
			eprintf("unexpected archive_read_next_header return code %d on archive '%s': %s\n",
				ret, path, archive_error_string(a));
			return false;
		}
	}
	// unreachable
	return false;
}

static int feh_archive_read_next_header_op(struct archive *a, void *data)
{
	struct feh_archive_read_next_header_op_args *args = data;
	return archive_read_next_header(a, &args->entry);
}

static int feh_archive_read_data_into_fd_op(struct archive *a, void *data)
{
	struct feh_archive_read_data_into_fd_op_args *args = data;
	return archive_read_data_into_fd(a, args->fd);
}

#endif /* HAVE_LIBARCHIVE */
