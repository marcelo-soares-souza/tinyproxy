/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2003 Robert James Kaes <rjkaes@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Misc. routines which are used by the various functions to handle strings
 * and memory allocation and pretty much anything else we can think of. Also,
 * the load cutoff routine is in here. Could not think of a better place for
 * it, so it's in here.
 */

#include "main.h"

#include "conns.h"
#include "heap.h"
#include "http-message.h"
#include "log.h"
#include "utils.h"

/*
 * Build the data for a complete HTTP & HTML message for the client.
 */
int
send_http_message (struct conn_s *connptr, int http_code,
                   const char *error_title, const char *message)
{
        static const char *headers[] = {
                "Server: " PACKAGE "/" VERSION,
                "Content-type: text/html",
                "Connection: close"
        };

        http_message_t msg;

        msg = http_message_create (http_code, error_title);
        if (msg == NULL)
                return -1;

        http_message_add_headers (msg, headers, 3);
        http_message_set_body (msg, message, strlen (message));
        http_message_send (msg, connptr->client_fd);
        http_message_destroy (msg);

        return 0;
}

/*
 * Safely creates filename and returns the low-level file descriptor.
 */
int create_file_safely (const char *filename, unsigned int truncate_file)
{
        struct stat lstatinfo;
        int fildes;

        /*
         * lstat() the file. If it doesn't exist, create it with O_EXCL.
         * If it does exist, open it for writing and perform the fstat()
         * check.
         */
        if (lstat (filename, &lstatinfo) < 0) {
                /*
                 * If lstat() failed for any reason other than "file not
                 * existing", exit.
                 */
                if (errno != ENOENT) {
                        fprintf (stderr,
                                 "%s: Error checking file %s: %s\n",
                                 PACKAGE, filename, strerror (errno));
                        return -EACCES;
                }

                /*
                 * The file doesn't exist, so create it with O_EXCL to make
                 * sure an attacker can't slip in a file between the lstat()
                 * and open()
                 */
                if ((fildes =
                     open (filename, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0) {
                        fprintf (stderr, "%s: Could not create file %s: %s\n",
                                 PACKAGE, filename, strerror (errno));
                        return fildes;
                }
        } else {
                struct stat fstatinfo;
                int flags;

                flags = O_RDWR;
                if (!truncate_file)
                        flags |= O_APPEND;

                /*
                 * Open an existing file.
                 */
                if ((fildes = open (filename, flags)) < 0) {
                        fprintf (stderr,
                                 "%s: Could not open file %s: %s\n",
                                 PACKAGE, filename, strerror (errno));
                        return fildes;
                }

                /*
                 * fstat() the opened file and check that the file mode bits,
                 * inode, and device match.
                 */
                if (fstat (fildes, &fstatinfo) < 0
                    || lstatinfo.st_mode != fstatinfo.st_mode
                    || lstatinfo.st_ino != fstatinfo.st_ino
                    || lstatinfo.st_dev != fstatinfo.st_dev) {
                        fprintf (stderr,
                                 "%s: The file %s has been changed before it could be opened\n",
                                 PACKAGE, filename);
                        close (fildes);
                        return -EIO;
                }

                /*
                 * If the above check was passed, we know that the lstat()
                 * and fstat() were done on the same file. Now we check that
                 * there's only one link, and that it's a normal file (this
                 * isn't strictly necessary because the fstat() vs lstat()
                 * st_mode check would also find this)
                 */
                if (fstatinfo.st_nlink > 1 || !S_ISREG (lstatinfo.st_mode)) {
                        fprintf (stderr,
                                 "%s: The file %s has too many links, "
                                 "or is not a regular file: %s\n",
                                 PACKAGE, filename, strerror (errno));
                        close (fildes);
                        return -EMLINK;
                }

                /*
                 * Just return the file descriptor if we _don't_ want the file
                 * truncated.
                 */
                if (!truncate_file)
                        return fildes;

                /*
                 * On systems which don't support ftruncate() the best we can
                 * do is to close the file and reopen it in create mode, which
                 * unfortunately leads to a race condition, however "systems
                 * which don't support ftruncate()" is pretty much SCO only,
                 * and if you're using that you deserve what you get.
                 * ("Little sympathy has been extended")
                 */
#ifdef HAVE_FTRUNCATE
                if (ftruncate (fildes, 0) != 0) {
                        log_message (LOG_WARNING,
                                     "Unable to truncate file '%s'", filename);
                }
#else
                close (fildes);
                if ((fildes =
                     open (filename, O_RDWR | O_CREAT | O_TRUNC, 0600)) < 0) {
                        fprintf (stderr, "%s: Could not open file %s: %s.",
                                 PACKAGE, filename, strerror (errno));
                        return fildes;
                }
#endif /* HAVE_FTRUNCATE */
        }

        return fildes;
}

/**
 * pidfile_create:
 * @filename: The name of the file which should be created.
 *
 * Creates a file with the PID of the Tinyproxy process.
 *
 * Returns: %0 on success, non-zero values on errors.
 **/
int
pidfile_create (const char *filename)
{
        int fildes;
        FILE *fd;

        /*
         * Create a new file
         */
        if ((fildes = create_file_safely (filename, TRUE)) < 0)
                return fildes;

        /*
         * Open a stdio file over the low-level one.
         */
        if ((fd = fdopen (fildes, "w")) == NULL) {
                fprintf (stderr,
                         "%s: Could not write PID file %s: %s.",
                         PACKAGE, filename, strerror (errno));
                close (fildes);
                unlink (filename);
                return -EIO;
        }

        fprintf (fd, "%d\n", getpid ());
        fclose (fd);
        return 0;
}

/*
 * Base 64 encoding
 */
static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void encode_base_64(char* src, char* dest, int max_len) {
    int n, l, i;
    l = strlen(src);
    max_len = (max_len - 1) / 4;
    for (i = 0; i < max_len; i++, src += 3, l -= 3) {
        switch (l) {
            case 0:
                break;
            case 1:
                n = src[0] << 16;
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = '=';
                *dest++ = '=';
                break;
            case 2:
                n = src[0] << 16 | src[1] << 8;
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = base64[(n >> 6) & 077];
                *dest++ = '=';
                break;
            default:
                n = src[0] << 16 | src[1] << 8 | src[2];
                *dest++ = base64[(n >> 18) & 077];
                *dest++ = base64[(n >> 12) & 077];
                *dest++ = base64[(n >> 6) & 077];
                *dest++ = base64[n & 077];
        }
        if (l < 3) break;
    }
    *dest++ = 0;
}

/*
 * Replaces in the string str all the occurrences of the source string old with
 * the destination string new.
 */
char *repl_str(const char *str, const char *old, const char *new) {

    /* Adjust each of the below values to suit your needs. */

    /* Increment positions cache size initially by this number. */
    size_t cache_sz_inc = 16;
    /* Thereafter, each time capacity needs to be increased,
     * multiply the increment by this factor. */
    const size_t cache_sz_inc_factor = 3;
    /* But never increment capacity by more than this number. */
    const size_t cache_sz_inc_max = 1048576;

    char *pret, *ret = NULL;
    const char *pstr2, *pstr = str;
    size_t i, count = 0;
    ptrdiff_t *pos_cache = NULL;
    size_t cache_sz = 0;
    size_t cpylen, orglen, retlen, newlen, oldlen = strlen(old);

    /* Find all matches and cache their positions. */
    while ((pstr2 = strstr(pstr, old)) != NULL) {
        count++;

        /* Increase the cache size when necessary. */
        if (cache_sz < count) {
            cache_sz += cache_sz_inc;
            pos_cache = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
            if (pos_cache == NULL) {
                goto end_repl_str;
            }
            cache_sz_inc *= cache_sz_inc_factor;
            if (cache_sz_inc > cache_sz_inc_max) {
                cache_sz_inc = cache_sz_inc_max;
            }
        }

        pos_cache[count-1] = pstr2 - str;
        pstr = pstr2 + oldlen;
    }

    orglen = pstr - str + strlen(pstr);

    /* Allocate memory for the post-replacement string. */
    if (count > 0) {
        newlen = strlen(new);
        retlen = orglen + (newlen - oldlen) * count;
    } else  retlen = orglen;
    ret = malloc(retlen + 1);
    if (ret == NULL) {
        goto end_repl_str;
    }

    if (count == 0) {
        /* If no matches, then just duplicate the string. */
        strcpy(ret, str);
    } else {
        /* Otherwise, duplicate the string whilst performing
         * the replacements using the position cache. */
        pret = ret;
        memcpy(pret, str, pos_cache[0]);
        pret += pos_cache[0];
        for (i = 0; i < count; i++) {
            memcpy(pret, new, newlen);
            pret += newlen;
            pstr = str + pos_cache[i] + oldlen;
            cpylen = (i == count-1 ? orglen : pos_cache[i+1]) - pos_cache[i] - oldlen;
            memcpy(pret, pstr, cpylen);
            pret += cpylen;
        }
        ret[retlen] = '\0';
    }

end_repl_str:
    /* Free the cache and return the post-replacement string,
     * which will be NULL in the event of an error. */
    free(pos_cache);
    return ret;
}
