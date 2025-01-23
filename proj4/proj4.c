// Ben Smith bxs566 proj4.c 11/07/2024 trace file analyzer

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>	  /* ip proto nums */
#include <net/ethernet.h> /* ethernet header struct */
#include <netinet/ip.h>	  /* ip header struct */
#include <netinet/udp.h>  /* udp header struct */
#include <netinet/tcp.h>  /* tcp header struct */
#include <arpa/inet.h>
#include "next.h"

#define ARG_INFO 0x1
#define ARG_SIZE 0x2
#define ARG_TCP 0x4
#define ARG_MATRIX 0x8
#define ERROR 1

unsigned short cmd_line_flags = 0;
char *tracefilename = NULL;
struct tcp_node *matrix_head = NULL;

// tcp connection structure
// tcp connection node structure
// linked list of tcp connection nodes
// using a tree would be far more efficient. not implemented due to time constraints

struct tcp_conn
{
	char *s_ip, *d_ip;
	int pkts;
	unsigned long vol;
};

struct tcp_node
{
	struct tcp_conn conn;
	char *key; /* source ip appended with dest ip */
	struct tcp_node *next;
};

int usage(char *progname)
{
	fprintf(stderr, "%s -r trace_file -i|-s|-t|-m\n", progname);
	fprintf(stderr, "   -r X  specify trace file \'X\' to read from\n");
	fprintf(stderr, "   -i    run in trace information mode\n");
	fprintf(stderr, "   -s    run in size analysis mode\n");
	fprintf(stderr, "   -t    run in TCP packet printing mode\n");
	fprintf(stderr, "   -m    run in traffic matrix mode\n");
	exit(ERROR);
}

void parseargs(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "istmr:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			cmd_line_flags |= ARG_INFO;
			break;
		case 's':
			cmd_line_flags |= ARG_SIZE;
			break;
		case 't':
			cmd_line_flags |= ARG_TCP;
			break;
		case 'm':
			cmd_line_flags |= ARG_MATRIX;
			break;
		case 'r':
			tracefilename = optarg;
			break;
		case '?':
		default:
			printf("FLAG: %c\n", opt);
			fprintf(stderr, "error: unexpected flag\n");
			usage(argv[0]);
		}
	}
}

void print_info(int fd, struct pkt_info pkt)
{
	struct pkt_info first_pkt, last_pkt;
	unsigned short next = next_packet(fd, &pkt);
	unsigned int pkts = 0, ip_pkts = 0;
	first_pkt = pkt;

	while (next == 1)
	{
		pkts++;
		if (pkt.ethh != NULL && pkt.ethh->ether_type == ETHERTYPE_IP)
			ip_pkts++;
		last_pkt = pkt;
		next = next_packet(fd, &pkt);
	}

	printf("%s %f %f %u %u\n", tracefilename, first_pkt.now, last_pkt.now - first_pkt.now, pkts, ip_pkts);
}

void print_size(int fd, struct pkt_info pkt)
{
	unsigned short next = next_packet(fd, &pkt);

	while (next == 1)
	{
		if (pkt.ethh == NULL || pkt.ethh->ether_type != ETHERTYPE_IP)
		{
			next = next_packet(fd, &pkt);
			continue;
		}
		printf("%f %u ", pkt.now, pkt.caplen);
		if (pkt.iph == NULL)
			printf("- - - - -");
		else
		{
			printf("%u %u ", pkt.iph->tot_len, (uint8_t)pkt.iph->ihl * 4);

			if (pkt.iph->protocol != 6 && pkt.iph->protocol != 17)
				printf("? ? ?");
			else if (pkt.tcph != NULL)
				printf("T %u %u", ((uint8_t)pkt.tcph->doff * 4), pkt.iph->tot_len - ((uint8_t)pkt.iph->ihl * 4) - ((uint8_t)pkt.tcph->doff * 4));
			else if (pkt.udph != NULL)
				printf("U 8 %u", pkt.iph->tot_len - ((uint8_t)pkt.iph->ihl * 4) - 8);
			else
				printf("%c - -", (pkt.iph->protocol == 6) ? 'T' : 'U');
		}
		printf("\n");

		next = next_packet(fd, &pkt);
	}
}

void print_tcp(int fd, struct pkt_info pkt)
{
	unsigned short next = next_packet(fd, &pkt);

	while (next == 1)
	{
		struct in_addr source, dest;
		char *s_ip, *d_ip;

		if (pkt.iph != NULL && pkt.tcph != NULL && pkt.iph->protocol == 6)
		{
			printf("%f ", pkt.now);
			source.s_addr = pkt.iph->saddr;
			s_ip = inet_ntoa(source);
			printf("%s %u ", s_ip, pkt.tcph->source);
			dest.s_addr = pkt.iph->daddr;
			d_ip = inet_ntoa(dest);
			printf("%s %u ", d_ip, pkt.tcph->dest);
			printf("%u %u %c %u %u\n", pkt.iph->ttl, pkt.iph->id, (pkt.tcph->syn) ? 'Y' : 'N', pkt.tcph->window, pkt.tcph->seq);
		}
		next = next_packet(fd, &pkt);
	}
}

void make_matrix(struct tcp_conn conn)
{
	/* hash connection, search linked list
	   if in linked list, update count and volume and free strings
	   else add node using existing strings */
	char *key = malloc(strlen(conn.s_ip) + strlen(conn.d_ip) + 1);
	if (key == NULL)
	{
		errexit("error: cannot hash connection");
	}

	strcpy(key, conn.s_ip);
	strcat(key, conn.d_ip);

	if (matrix_head == NULL)
	{
		struct tcp_node *node = malloc(sizeof(struct tcp_node));
		if (node == NULL)
			errexit("error: could not allocate node");
		node->conn = conn;
		node->key = strdup(key);
		node->next = NULL;
		matrix_head = node;
	}
	else
	{
		struct tcp_node *node = matrix_head;
		while (node != NULL && (strcmp(key, node->key) != 0))
			node = node->next;

		if (node != NULL)
		{
			node->conn.pkts++;
			node->conn.vol += conn.vol;
			free(conn.s_ip);
			free(conn.d_ip);
		}
		else
		{
			struct tcp_node *new_node = malloc(sizeof(struct tcp_node));
			if (new_node == NULL)
				errexit("error: could not allocate node");
			new_node->conn = conn;
			new_node->key = strdup(key);
			new_node->next = matrix_head;
			matrix_head = new_node;
		}
	}
	free(key);
}

void print_matrix(int fd, struct pkt_info pkt)
{
	unsigned short next = next_packet(fd, &pkt);
	while (next == 1)
	{
		if (pkt.iph != NULL && pkt.tcph != NULL && pkt.iph->protocol == 6)
		{
			struct tcp_conn this_conn;
			struct in_addr source, dest;

			source.s_addr = pkt.iph->saddr;
			this_conn.s_ip = strdup(inet_ntoa(source));
			if (this_conn.s_ip == NULL)
				errexit("error: could not process ip");

			dest.s_addr = pkt.iph->daddr;
			this_conn.d_ip = strdup(inet_ntoa(dest));
			if (this_conn.d_ip == NULL)
				errexit("error: could not process ip");

			this_conn.vol = pkt.iph->tot_len - ((uint8_t)pkt.iph->ihl * 4) - ((uint8_t)pkt.tcph->doff * 4);
			this_conn.pkts = 1;

			make_matrix(this_conn);
		}

		next = next_packet(fd, &pkt);
	}

	struct tcp_node *node = matrix_head;
	struct tcp_node *old;
	while (node != NULL)
	{
		printf("%s %s %u %lu\n", node->conn.s_ip, node->conn.d_ip, node->conn.pkts, node->conn.vol);
		old = node;
		node = node->next;
		free(old->key);
		free(old->conn.d_ip);
		free(old->conn.s_ip);
		free(old);
	}
}

int main(int argc, char *argv[])
{
	parseargs(argc, argv);

	if (tracefilename == NULL)
	{
		fprintf(stderr, "error: specify trace file\n");
		usage(argv[0]);
	}

	int tracefile = open(tracefilename, O_RDONLY);
	if (tracefile < 0)
		errexit("error: cannot open trace file");
	struct pkt_info cur_pkt;

	switch (cmd_line_flags)
	{
	case (ARG_INFO):
		print_info(tracefile, cur_pkt);
		break;
	case (ARG_MATRIX):
		print_matrix(tracefile, cur_pkt);
		break;
	case (ARG_SIZE):
		print_size(tracefile, cur_pkt);
		break;
	case (ARG_TCP):
		print_tcp(tracefile, cur_pkt);
		break;
	default:
		errexit("error: specify exactly one of -i|-m|-s|-t");
	}
	close(tracefile);
}