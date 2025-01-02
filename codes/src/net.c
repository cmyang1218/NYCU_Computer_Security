#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t ip_cksum(void *in, int sz)
{
	long sum = 0;
	unsigned short *ptr = (unsigned short *)in;

	for(; sz > 1; sz -= 2) sum += *ptr++;
	if(sz > 0) sum += *((unsigned char *)ptr);
	while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}
uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
	uint8_t* ip_hdr = (uint8_t *)&iphdr;
	uint16_t sum = ip_cksum(ip_hdr, iphdr.ihl << 2);
	return sum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
	struct iphdr *ip_hdr = (struct iphdr *)pkt;
	uint16_t cksum = cal_ipv4_cksm(*ip_hdr);

	if(cksum != 0){
		// fprintf(stderr, "Checksum error while dissecting ip header\n");
	}
	uint32_t saddr = ntohl(ip_hdr->saddr), daddr = ntohl(ip_hdr->daddr);
	
	memcpy(self->src_ip, &saddr, 4);
	memcpy(self->dst_ip, &daddr, 4);
	memcpy(self->x_src_ip, &daddr, 4);
	memcpy(self->x_dst_ip, &saddr, 4);

	memcpy(&(self->ip4hdr), pkt, sizeof(struct iphdr));
	self->pro = ip_hdr->protocol;
	self->plen = pkt_len - sizeof(struct iphdr);
	
	return pkt + sizeof(struct iphdr); 
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
	memcpy(&(self->ip4hdr.saddr), self->x_src_ip, 4);
	memcpy(&(self->ip4hdr.daddr), self->x_dst_ip, 4);
	self->ip4hdr.saddr = htonl(self->ip4hdr.saddr);
	self->ip4hdr.daddr = htonl(self->ip4hdr.daddr);

	self->ip4hdr.tot_len = htons(self->hdrlen + self->plen);
	self->ip4hdr.check = 0;
	uint16_t cksum = cal_ipv4_cksm(self->ip4hdr);
	self->ip4hdr.check = cksum;
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
