/*
 * (C) Copyright 2014, Stephen M. Cameron.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

static char *programname;

static char *slurp_file(char *f, off_t *textsize)
{
	int fd;
	struct stat statbuf;
	off_t bytesleft, bytesread;
	char *fileptr = NULL;
	char *slurped_file = NULL;

	fd = open(f, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Cannot open '%s': %s\n",
				programname, f, strerror(errno));
		return NULL;
	}
	if (fstat(fd, &statbuf) != 0) {
		fprintf(stderr, "%s: Cannot stat '%s': %s\n",
				programname, f, strerror(errno));
		close(fd);
		return NULL;
	}
	bytesleft = statbuf.st_size; 
	slurped_file = malloc(bytesleft + 1);
	fileptr = slurped_file;
	if (!slurped_file) {
		fprintf(stderr, "%s: malloc returned NULL, out of memory\n",
			programname);
		goto bail_out;
	}
	memset(slurped_file, 0, bytesleft + 1);
	do {
		bytesread = read(fd, fileptr, bytesleft);
		if (bytesread < 0 && errno == EAGAIN)
			continue;
		if (bytesread < 0) {
			fprintf(stderr, "%s: error reading '%s: %s'\n",
				programname, f, strerror(errno));
			goto bail_out;
		}
		if (bytesread == 0) {
			fprintf(stderr, "%s: unexpected EOF in %s\n",
				programname, f); 
			goto bail_out;
		}
		fileptr += bytesread;
		bytesleft -= bytesread;
	} while (bytesleft > 0);

	*textsize = statbuf.st_size;

	close(fd);
	return slurped_file;

bail_out:
	if (slurped_file)
		free(slurped_file);
	close(fd);
	return NULL;
}

static int detect_buggy_yacc(char *text)
{
	char *x;

	x = strstr(text, " #line ");
	if (!x)
		return 0;
	return 1; 
}

static void fixup_buggy_yacc_file(char *f)
{
	char *slurped_file, *x;
	off_t textsize;
	char *newname;
	int fd;
	off_t bytesleft, byteswritten;

	newname = alloca(strlen(f) + 10);
	strcpy(newname, "broken-");
	strcat(newname, f);

	slurped_file = slurp_file(f, &textsize);
	if (!slurped_file)
		return;
	if (!detect_buggy_yacc(slurped_file))
		return;

	x = slurped_file;


	/*
	 * Fixup the '#line' directives which yacc botched.
	 * Note: this is vulnerable to false positives, but
	 * since this program is just a hack to make this particular
	 * program work, it is sufficient for our purposes.
	 * regexp could make this better, but the real fix needs
	 * to be made in yacc/bison.
	 */
	while ((x = strstr(x, " #line ")) != NULL) {
		*x = '\n';
	}

	if (rename(f, newname) != 0) {
		fprintf(stderr, "%s: Failed to rename '%s' to '%s': %s\n",
				programname, f, newname, strerror(errno));
		return;
	}
	fd = open(f, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to create '%s': %s\n",
			programname, f, strerror(errno));
		return;
	}

	bytesleft = textsize;
	x = slurped_file;
	do {
		byteswritten = write(fd, x, bytesleft); 
		if (byteswritten < 0) {
			fprintf(stderr, "%s: Error writing '%s': %s\n",
				programname, f, strerror(errno)); 
			return;
		}
		if (byteswritten == 0 && errno == EINTR)
			continue;
		x += byteswritten;
		bytesleft -= byteswritten;
	} while (bytesleft > 0);
	close(fd);
}

int main(int argc, char *argv[])
{
	int i;

	programname = argv[0];

	for (i = 1; i < argc; i++)
		fixup_buggy_yacc_file(argv[i]);
	return 0;
}
