// Benjamin Smith bxs566 proj1.c 09/17/2024
// ipv4 address validator
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define ARG_SUMMARY 0x1
#define ARG_LIST 0x2
#define STR_END '\0'
#define BUFFER_SIZE 1024
#define NUM_QUADS 4

char *filename = NULL;
FILE *file;
unsigned short cmd_line_flags = 0;
int input_lines;
int valid_ips;
int invalid_ips;

int validateip(char **ip)
{
	char *quad;
	int quad_count = 0;
	unsigned short is_valid = 1;
	while ((quad = strsep(ip, ".")) != NULL && is_valid)
	{
		quad_count++;
		int quad_len = strlen(quad);
		if (quad_len > 3)
			is_valid = 0;
		else if (quad_len == 0)
			is_valid = 0;
		else if (quad_len > 1 && quad[0] == '0')
			is_valid = 0;
		else if (atoi(quad) > 255)
			is_valid = 0;
		else
		{
			for (char *c = &quad[0]; *c != STR_END; c++)
			{
				if (!(isdigit(*c)))
					is_valid = 0;
			}
		}
	}
	if (quad_count != NUM_QUADS)
		is_valid = 0;
	return (is_valid);
}

void usage(char *progname)
{
	fprintf(stderr, "%s [-s] [-l] -f filename\n", progname);
	fprintf(stderr, "    -s    run in summary mode\n");
	fprintf(stderr, "    -l    run in list mode\n");
	fprintf(stderr, "    -f X  specify input file \'X\'\n");
	exit(1);
}

void parseargs(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "slf:")) != -1)
	{
		switch (opt)
		{
		case 's':
			cmd_line_flags |= ARG_SUMMARY;
			break;
		case 'l':
			cmd_line_flags |= ARG_LIST;
			break;
		case 'f':
			filename = optarg;
			break;
		case '?':
		default:
			usage(argv[0]);
		}
	}
	if (cmd_line_flags == 0)
	{
		fprintf(stderr, "error: specify either -s or -l\n");
		usage(argv[0]);
	}
}

int summinput(FILE *file)
{
	char *buffer = malloc(BUFFER_SIZE);
	if (buffer == NULL)
	{
		fprintf(stderr, "error: cannot allocate memory\n");
		return 1;
	}
	while (fgets(buffer, BUFFER_SIZE, file) != NULL)
	{
		input_lines++;
		char *line = strdup(buffer);
		char *line_ptr = line;
		if (line == NULL)
		{
			fprintf(stderr, "error: cannot allocate memory\n");
			return 1;
		}
		line[strcspn(line, "\n")] = 0;	// remove newline
		if (validateip(&line))
			valid_ips++;
		else
			invalid_ips++;
		free(line_ptr);
	}
	printf("LINES: %d\n", input_lines);
	printf("VALID: %d\n", valid_ips);
	printf("INVALID: %d\n", invalid_ips);
	free(buffer);
	return 0;
}

int listinput(FILE *file)
{
	char *buffer = malloc(BUFFER_SIZE);
	if (buffer == NULL)
	{
		fprintf(stderr, "error: cannot allocate memory\n");
		return 1;
	}
	while (fgets(buffer, BUFFER_SIZE, file) != NULL)
	{
		input_lines++;
		char *line = strdup(buffer);
		if (line == NULL)
		{
			fprintf(stderr, "error: cannot allocate memory\n");
			return 1;
		}
		line[strcspn(line, "\n")] = 0;	// remove newline
		char *line_copy = strdup(line); // preserve original line
		char *line_copy_ptr = line_copy;
		char is_valid;
		if (validateip(&line_copy))
			is_valid = '+';
		else
			is_valid = '-';
		printf("%s %c\n", line, is_valid);
		free(line);
		free(line_copy_ptr);
	}
	free(buffer);
	return 0;
}

int main(int argc, char *argv[])
{
	parseargs(argc, argv);
	int error = 0;

	if (filename == NULL)
	{
		fprintf(stderr, "error: filename required\n");
	}

	file = fopen(filename, "r");
	if (file == NULL)
	{
		fprintf(stderr, "error: cannot open file %s\n", filename);
		error = 1;
	}

	if (cmd_line_flags == ARG_SUMMARY)
	{
		// run in summary mode
		error = summinput(file);
	}
	else if (cmd_line_flags == ARG_LIST)
	{
		// run in list mode
		error = listinput(file);
	}
	else
	{
		fprintf(stderr, "error: specify exactly one of -s and -l \n");
		error = 1;
	}
	fclose(file);
	exit(error);
}