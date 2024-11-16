
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "next.h"

void errexit (char *msg)
{
    fprintf (stdout,"%s\n",msg);
    exit (1);
}

/*  fd - an open file to read packets from
	pinfo - allocated memory to put packet info into for one packet
	returns:
	1 - a packet was read and pinfo is setup for processing the packet
	0 - we have hit the end of the file and no packet is available
*/
unsigned short next_packet(int fd, struct pkt_info *pinfo)
{
	struct meta_info meta;
	int bytes_read;
	memset(pinfo, 0x0, sizeof(struct pkt_info));
	memset(&meta, 0x0, sizeof(struct meta_info));

	/* read the meta information */
	bytes_read = read(fd, &meta, sizeof(meta));
	if (bytes_read == 0)
		return (0);
	if (bytes_read < sizeof(meta))
		errexit("error: cannot read meta information");
	pinfo->caplen = ntohs(meta.caplen);
	/* set pinfo->now based on meta.secs & meta.usecs */
	pinfo->now = (double)(ntohl(meta.secs) + (ntohl(meta.usecs) * 0.000001));
	if (pinfo->caplen == 0)
		return (1);
	if (pinfo->caplen > MAX_PKT_SIZE)
		errexit("error: packet too big");

	/* read the packet contents */
	bytes_read = read(fd, pinfo->pkt, pinfo->caplen);
	if (bytes_read < 0)
		errexit("error: error reading packet");
	if (bytes_read < pinfo->caplen)
		errexit("error: unexpected end of file encountered");

	if (bytes_read < sizeof(struct ether_header))
		return (1);
	pinfo->ethh = (struct ether_header *)pinfo->pkt;
	pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
	if (pinfo->ethh->ether_type != ETHERTYPE_IP)
		/* nothing more to do with non-IP packets */
		return (1);
	if (pinfo->caplen == sizeof(struct ether_header))
		/* we don't have anything beyond the ethernet header
		to process */
		return (1);

	/* set pinfo->iph to start of IP header */
	pinfo->iph = (struct iphdr *)(pinfo->pkt + sizeof(struct ether_header));
	pinfo->iph->tot_len = ntohs(pinfo->iph->tot_len);
	pinfo->iph->id = ntohs(pinfo->iph->id);
	pinfo->iph->ihl = pinfo->iph->ihl;
	if (pinfo->caplen == sizeof(struct ether_header) + ((uint8_t)pinfo->iph->ihl) * 4)
		return (1);
	/* if TCP packet,
	set pinfo->tcph to the start of the TCP header
	setup values in pinfo->tcph, as needed */
	if (pinfo->iph->protocol == 6)
	{
		pinfo->tcph = (struct tcphdr *)(pinfo->pkt + sizeof(struct ether_header) + (uint8_t)pinfo->iph->ihl * 4);
		pinfo->tcph->source = ntohs(pinfo->tcph->source);
		pinfo->tcph->dest = ntohs(pinfo->tcph->dest);
		pinfo->tcph->window = ntohs(pinfo->tcph->window);
		pinfo->tcph->seq = ntohl(pinfo->tcph->seq);
		pinfo->udph = NULL;
	}
	/* if UDP packet,
	set pinfo->udph to the start of the UDP header,
	setup values in pinfo->udph, as needed */
	else if (pinfo->iph->protocol == 17)
	{
		pinfo->udph = (struct udphdr *)(pinfo->pkt + sizeof(struct ether_header) + (uint8_t)pinfo->iph->ihl * 4);
		pinfo->udph->source = ntohs(pinfo->udph->source);
		pinfo->udph->dest = ntohs(pinfo->udph->dest);
		pinfo->udph->len = ntohs(pinfo->udph->len);
		pinfo->tcph = NULL;
	}
	else
	{
		pinfo->tcph = NULL;
		pinfo->udph = NULL;
	}
	return (1);
}
