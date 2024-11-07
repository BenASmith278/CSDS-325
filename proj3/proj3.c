// Ben Smith proj3.c 10/23/2024 simple socket-based HTTP server

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SUCCESS 0
#define ERROR 1
#define BUFFLEN 1024
#define PROTOCOL "tcp"
#define QLEN 1
#define BADREQ "HTTP/1.1 400 Malformed Request\r\n\r\n"
#define NOTIMPL "HTTP/1.1 501 Protocol Not Implemented\r\n\r\n"
#define UNSUPD "HTTP/1.1 405 Unsupported Method\r\n\r\n"
#define SHUTDN "HTTP/1.1 200 Server Shutting Down\r\n\r\n"
#define FORBDN "HTTP/1.1 403 Operation Forbidden\r\n\r\n"
#define BADFILE "HTTP/1.1 406 Invalid Filename\r\n\r\n"
#define OK "HTTP/1.1 200 OK\r\n\r\n"
#define NOTFND "HTTP/1.1 404 File Not Found\r\n\r\n"
#define HEADEND "\r\n\r\n"

typedef struct Request
{
	char *method, *arg, *protocol;
} Request;

char *port = NULL;
char *directory = NULL;
char *auth_token = NULL;
char responsehead[BUFFLEN];
int sd, sd2, alive;
unsigned short portnum;
Request request;

void usage(char *progname)
{
	fprintf(stderr, "%s -p port -r directory -t auth_token\n", progname);
	fprintf(stderr, "   -p P  specify port \'P\' on which the server will run\n");
	fprintf(stderr, "   -r R  specify directory \'R\' form which files will be served\n");
	fprintf(stderr, "   -t T  specify access token \'T\' used to shutdown server\n");
	exit(ERROR);
}

void parseargs(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "p:r:t:")) != -1)
	{
		switch (opt)
		{
		case 'p':
			port = optarg;
			break;
		case 'r':
			directory = optarg;
			break;
		case 't':
			auth_token = optarg;
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
	fprintf(stderr, "ERRNO: %s\n", strerror(errno));
	exit(ERROR);
}

void makesocket()
{
	struct sockaddr_in sin;
	struct protoent *protoinfo;

	/* determine protocol */
	if ((protoinfo = getprotobyname(PROTOCOL)) == NULL)
		errexit("error: cannot find protocol information for %s", PROTOCOL);

	/* setup endpoint info */
	memset((char *)&sin, 0x0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(portnum);

	/* allocate a socket */
	sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
	if (sd < 0)
		errexit("error: cannot create socket", NULL);

	/* bind the socket */
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		errexit("error: cannot bind to port %s", port);
}

void listensocket()
{
	struct sockaddr addr;
	unsigned int addrlen;

	/* listen for incoming connections */
	if (listen(sd, QLEN) < 0)
		errexit("error: cannot listen on port %s", port);

	/* accept a connection */
	addrlen = sizeof(addr);
	sd2 = accept(sd, &addr, &addrlen);
	if (sd2 < 0)
		errexit("error: could not accept connection", NULL);
}

void sendheader(char *message)
{
	memset(responsehead, 0x0, BUFFLEN);
	memcpy(responsehead, message, strlen(message));
	if (write(sd2, responsehead, strlen(message)) < 0)
		errexit("error: could not write to socket", NULL);
}

void sendfile(char *filepath)
{
	int bytes;
	char filebuffer[BUFFLEN];
	FILE *file;
	if ((file = fopen(filepath, "r+")) == NULL)
	{
		sendheader(NOTFND);
		return;
	}

	sendheader(OK);
	while ((bytes = fread(filebuffer, 1, BUFFLEN, file)) > 0)
	{
		write(sd2, filebuffer, bytes);
	}
	fclose(file);
}

int checkcrlf(char *buffer)
{
	char buffercopy[BUFFLEN];
	memset(buffercopy, 0x0, BUFFLEN);
	strcpy(buffercopy, buffer);

	char *line = strtok(buffercopy, "\n");
	while (line != NULL)
	{
		if (strcmp((line + strlen(line) - 1), "\r") != 0)
			return ERROR;
		line = strtok(NULL, "\n");
	}

	return SUCCESS;
}

int validaterequest(char *buffer, int length)
{
	char buffercopy[BUFFLEN];
	memset(buffercopy, 0x0, BUFFLEN);
	strcpy(buffercopy, buffer);

	/* check METHOD ARGUMENT HTTP/VERSION\r\n */
	request.method = strtok(buffercopy, " ");
	request.arg = strtok(NULL, " ");
	request.protocol = strtok(NULL, " ");
	if (request.method == NULL || request.arg == NULL || request.protocol == NULL)
		return ERROR;

	/* find first line end, check if correct ('\r\n$') or not (' .*$') */
	int eolspan = strcspn(request.protocol, "\r ");
	if (strncmp((request.protocol + eolspan) + 1, "\n", 1) != 0)
		return ERROR;

	/* check all lines end with \r\n */
	/* assuming a line is a string ending in \n */
	if (checkcrlf(buffer) != SUCCESS)
		return ERROR;
	/* if header somehow over 1024B */
	if (length == BUFFLEN)
	{
		do
		{
			length = read(sd2, buffer, BUFFLEN);
			if (checkcrlf(buffer) != SUCCESS)
				return ERROR;
		} while (length == BUFFLEN);
	}

	/* check final chars are \r\n\r\n */
	/* since lines (1, n) can be ignored, dont check if any \r\n\r\n before the end of the header */
	if (strcmp((buffer + length) - 4, HEADEND) != 0)
		return ERROR;

	return SUCCESS;
}

int get()
{
	/* filename does not start with '/' */
	if (strncmp(request.arg, "/", 1) != 0)
	{
		sendheader(BADFILE);
		return ERROR;
	}
	/* filename is only '/'*/
	else if (strcmp(request.arg, "/") == 0)
		request.arg = "/index.html";

	char *filepath;
	filepath = strcat(directory, request.arg);
	int exists = access(filepath, R_OK);
	if (exists < 0)
	{
		sendheader(NOTFND);
		return ERROR;
	}

	sendfile(filepath);
	return SUCCESS;
}

int killserver()
{
	if (strcmp(request.arg, auth_token) == 0)
	{
		alive = 0;
		close(sd);
		return SUCCESS;
	}
	else
		return ERROR;
}

void runrequest()
{
	request.method = strtok(request.method, " ");
	request.arg = strtok(request.arg, " ");
	if (strcmp(request.method, "GET") == 0)
	{
		get();
	}
	else if (strcmp(request.method, "SHUTDOWN") == 0)
	{
		if (killserver() == SUCCESS)
			sendheader(SHUTDN);
		else
			sendheader(FORBDN);
	}
	else
	{
		sendheader(UNSUPD);
	}
}

void readrequest()
{
	int bytes;
	char buffer[BUFFLEN];
	memset(buffer, 0x0, BUFFLEN);

	bytes = read(sd2, buffer, BUFFLEN);
	if (bytes < 0)
		errexit("error: cannot read from connection", NULL);

	/* handle anything that can return 400 */
	if (validaterequest(buffer, bytes) != SUCCESS)
	{
		sendheader(BADREQ);
		return;
	}

	/* handle 501 */
	if (strncmp(request.protocol, "HTTP/", 5) != 0)
	{
		sendheader(NOTIMPL);
		return;
	}

	runrequest();
}

void closesocket()
{
	close(sd2);
}

int main(int argc, char *argv[])
{
	parseargs(argc, argv);

	if (port == NULL)
	{
		fprintf(stderr, "error: port number required\n");
		usage(argv[0]);
	}
	else if (directory == NULL)
	{
		fprintf(stderr, "error: root directory required\n");
		usage(argv[0]);
	}
	else if (auth_token == NULL)
	{
		fprintf(stderr, "error: authentication token required\n");
		usage(argv[0]);
	}
	else
	{
		/* check that directory exists */
		int exists = access(directory, R_OK);
		if (exists < 0)
			errexit("error: cannot read root directory", NULL);

		portnum = strtoul(port, NULL, 10);

		makesocket();
		alive = 1;
		while (alive)
		{
			listensocket();
			readrequest();
			closesocket();
		}
	}

	exit(SUCCESS);
}