// Ben Smith proj2.c 10/07/2024 simple socket-based client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ERROR 1
#define ARG_INFO 0x0
#define ARG_PRINTHEAD 0x1
#define ARG_PRINTREQ 0x2
#define PROTO "tcp"
#define BUFLEN 1024
#define HTTP "http://"
#define OK "200 OK"
#define HEAD_END "\r\n\r\n"
#define HTTP_PORT 80

char *outfilename = NULL;
FILE *outfile;
unsigned short cmd_line_flags = 0;
char *url = NULL;
char *header = NULL;
char *hostname;
char *path;

void usage(char *progname)
{
	fprintf(stderr, "%s [-i] [-q] [-a] -u URL -w filename\n", progname);
	fprintf(stderr, "    -i    print debugging info\n");
	fprintf(stderr, "    -q    print HTTP request\n");
	fprintf(stderr, "    -a    print HTTP response header\n");
	fprintf(stderr, "    -u X  specify request URL \'X\'\n");
	fprintf(stderr, "    -w X  specify output file \'X\'\n");
	exit(ERROR);
}

void parseargs(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "iqau:w:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			cmd_line_flags |= ARG_INFO;
			break;
		case 'q':
			cmd_line_flags |= ARG_PRINTREQ;
			break;
		case 'a':
			cmd_line_flags |= ARG_PRINTHEAD;
			break;
		case 'u':
			url = optarg;
			break;
		case 'w':
			outfilename = optarg;
			break;
		case '?':
		default:
			usage(argv[0]);
		}
	}
}

int errexit(char *format, char *arg)
{
	fprintf(stderr, format, arg);
	fprintf(stderr, "\n");
	exit(ERROR);
}
void printinfo()
{
	printf("INFO: host: %s\n", hostname);
	printf("INFO: web_file: %s\n", path);
	printf("INFO: output_file: %s\n", outfilename);
}

void printrequest(char *request)
{
	char *line;
	line = strtok(request, "\r\n");
	while (line != NULL)
	{
		printf("REQ: %s\n", line);
		line = strtok(NULL, "\r\n");
	}
}

void printresponse()
{
	char *header_copy = strdup(header);
	char *line;
	if (header_copy == NULL)
		errexit("error: cannot print response header", NULL);

	line = strtok(header_copy, "\n");
	while (line != NULL)
	{
		if (strcmp(line, "\r") != 0) // leave at last \r
			printf("RSP: %s\n", line);
		else
			break;
		line = strtok(NULL, "\n");
	}
	free(header_copy);
}

int sethostinfo(char *arg_url)
{
	char *pathpart;

	// check starts with http://
	if (strncasecmp(arg_url, HTTP, strlen(HTTP)) != 0)
		errexit("error: URL must start with %s", HTTP);
	else
	{
		hostname = arg_url + strlen(HTTP);
		if (strcmp(hostname, "") == 0)
			errexit("error: cannot find hostname in URL: %s", arg_url);
	}

	// find hostname
	hostname = strtok(hostname, "/");
	if (hostname == NULL)
		errexit("error: cannot find hostname in URL: %s", arg_url);
	else
	{
		pathpart = strdup(hostname);
		char *pathpart_ptr = pathpart;
		path = malloc(strlen(hostname));
		pathpart = strtok(NULL, "/");
		while (pathpart != NULL)
		{
			strcat(path, "/");
			strcat(path, pathpart);
			pathpart = strtok(NULL, "/");
		}
		strcat(path, "/");
		free(pathpart_ptr);
	}

	return 0;
}

int makesocket(char *request)
{
	struct sockaddr_in sin;
	struct hostent *hinfo;
	struct protoent *protoinfo;
	int sd;

	/* lookup the hostname */
	hinfo = gethostbyname(hostname);
	if (hinfo == NULL)
		errexit("error: cannot find host: %s", hostname);

	/* set endpoint information */
	memset((char *)&sin, 0x0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(HTTP_PORT);
	memcpy((char *)&sin.sin_addr, hinfo->h_addr, hinfo->h_length);

	if ((protoinfo = getprotobyname(PROTO)) == NULL)
		errexit("error: cannot find protocol information for %s", PROTO);

	/* allocate a socket */
	sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
	if (sd < 0)
		errexit("error: cannot create socket", NULL);

	/* connect the socket */
	if (connect(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		errexit("error: cannot connect socket", NULL);

	send(sd, request, strlen(request), 0);
	return sd;
}

char *buildrequest()
{
	char *request = malloc(sizeof(path) + sizeof(hostname) + 80);
	sprintf(request, "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Case CSDS 325/425 WebClient 0.1\r\n\r\n", path, hostname);
	return request;
}

int writeoutfile(int sd)
{
	char buffer[BUFLEN];
	size_t header_size = 0;
	int out, isheader;

	isheader = 1;
	memset(buffer, 0x0, BUFLEN);

	while ((out = read(sd, buffer, BUFLEN - 1)) > 0)
	{
		buffer[out] = '\0';
		if (isheader)
		{
			header = realloc(header, header_size + out + 1);
			if (header == NULL)
				errexit("error: could not allocate header", NULL);
			memcpy(header + header_size, buffer, out);
			header_size += out;
			header[header_size] = '\0';

			char *header_end = strstr(header, HEAD_END);
			if (header_end != NULL)
			{
				isheader = 0;
				header_end += 4; // skip last \r\n\r\n
				if (strstr(header, OK) != NULL)  // 200 response
				{
					if (outfilename == NULL)
					{
						fprintf(stderr, "error: filename required\n");
					}
					outfile = fopen(outfilename, "w+");
					if (outfile == NULL)
					{
						fprintf(stderr, "error: cannot open file %s\n", outfilename);
						exit(ERROR);
					}
					fprintf(outfile, "%s", header_end);
				}
			}
		}
		else if (outfile != NULL)
		{
			fprintf(outfile, "%s", buffer);
		}
		memset(buffer, 0x0, BUFLEN);
	}
	
	if (out < 0)
		errexit("error: cannot read socket", NULL);
	if (outfile != NULL)
		fclose(outfile);
	return 0;
}

int sendrequest(int flag)
{
	char *req = buildrequest();
	int sd = makesocket(req);
	writeoutfile(sd);
	if (flag == ARG_INFO)
		printinfo();
	else if (flag == ARG_PRINTHEAD)
		printresponse();
	else if (flag == ARG_PRINTREQ)
		printrequest(req);
	else
		errexit("error: specify a flag", NULL);

	close(sd);
	free(req);
	free(header);
	return 0;
}

int main(int argc, char *argv[])
{
	parseargs(argc, argv);
	int error = 0;

	if (url == NULL)
	{
		fprintf(stderr, "error: URL required\n");
		usage(argv[0]);
	}

	if (url == NULL)
	{
		fprintf(stderr, "error: URL required\n");
		usage(argv[0]);
	}
	else
	{
		sethostinfo(url);
	}

	if (cmd_line_flags == ARG_INFO)
	{
		sendrequest(ARG_INFO);
	}
	else if (cmd_line_flags == ARG_PRINTHEAD)
	{
		sendrequest(ARG_PRINTHEAD);
	}
	else if (cmd_line_flags == ARG_PRINTREQ)
	{
		sendrequest(ARG_PRINTREQ);
	}
	else
	{
		fprintf(stderr, "error: specify at most one of -i, -q, or -a\n");
		usage(argv[0]);
	}

	exit(error);
}