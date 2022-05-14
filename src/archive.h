/* archive.h

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

#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdbool.h>

/**
 * Checks if 'path' is a valid URI of the 'archive' schema.
 *
 * This method should be available even in builds without archives support (in
 * case someone will try to open a filelist generated with a version with
 * archives support using a version generated without archives support).
 */
bool feh_archive_is_uri(const char *path);

#ifdef HAVE_LIBARCHIVE

#include <sys/stat.h>

/**
 * Checks if 'path' is an archive in one of the supported formats.
 *
 * 'st' parameter should contain actual information about the path. This method
 * can make a 'stat' call itself, but because the caller already has 'stat'
 * information about the path in all real cases, it was decided (for now) to not
 * make an additional syscall and just use already existing information.
 */
bool feh_archive_is_supported(const char *path, const struct stat *st);

/**
 * Implementation of this callback doesn't own 'uri' memory. It shouldn't try to
 * free it. Also, this memory is not expected to be left in some modified state
 * by the callback. It should be constant, but in real code callbacks usually
 * don't treat 'const' qualifier gracefully, so it is omitted.
 */
typedef void (feh_archive_uri_cb_t)(/* const */ char *uri);

/**
 * Lists all files in the 'path' archive and passes them to the 'callback' in the
 * format of the 'archive' schema URI.
 * Does nothing if 'path' is not an archive in one of the supported formats.
 */
void feh_archive_foreach_uri(const char *path, feh_archive_uri_cb_t callback);

/**
 * Extracts a file represented by 'uri' from an archive into the file
 * descriptor. Returns true in case of success.
 *
 * This method may be very expensive because it can potentially decompress the
 * whole archive to extract only one file. And for many types of archives, this
 * behavior is not avoidable.
 */
bool feh_archive_extract_uri(/* const */ char *uri, int fd);

#endif /* HAVE_LIBARCHIVE */
#endif /* ARCHIVE_H */
