#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"
uint16_t tcp_cksum(void *in, int sz)
{
	long sum = 0;
	unsigned short *ptr = (unsigned short *)in;

	for(; sz > 1; sz -= 2) sum += *ptr++;
	if(sz > 0) sum += *((unsigned char *)ptr);
	while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}
uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
	int8_t buff_size = 12 + 20 + plen; 
	uint8_t *buff = (uint8_t *)calloc(buff_size, sizeof(uint8_t));
	
	//Fill pseudo header
	memcpy(buff, &(iphdr.saddr), 4);
	memcpy(buff + 4, &(iphdr.daddr), 4);
	uint8_t proto = TCP;
	memcpy(buff + 9, &(proto), 1);
	uint16_t tcp_len = htons(20 + plen);
	memcpy(buff + 10, &tcp_len, 2);
	
	//Fill tcp header
	uint8_t *tcp_hdr = (uint8_t *)&tcphdr;
	memcpy(buff + 12, tcp_hdr, 20);

	//Fill tcp payload
	memcpy(buff + 32, pl, plen);

	//Calculate checksum
	uint16_t sum = tcp_cksum(buff, buff_size);
	return sum;
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
	struct tcphdr *tcp_hdr = (struct tcphdr *)segm;
	uint8_t *tcp_pl = segm + sizeof(struct tcphdr);
	self->plen = segm_len - sizeof(struct tcphdr);

	self->x_src_port = ntohs(tcp_hdr->th_dport);
	self->x_dst_port = ntohs(tcp_hdr->th_sport);
	self->x_tx_seq = ntohl(tcp_hdr->th_ack);
	self->x_tx_ack = ntohl(tcp_hdr->th_seq) + self->plen;
	uint16_t cksum = cal_tcp_cksm(net->ip4hdr, *tcp_hdr, tcp_pl, segm_len - sizeof(struct tcphdr));
	if(cksum != 0){
		// fprintf(stderr, "Checksum error while dissecting tcp header\n");
	}
	memcpy(&(self->thdr), segm, sizeof(struct tcphdr));

	return segm + sizeof(struct tcphdr);
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
	self->thdr.th_sport = htons(self->x_src_port);
	self->thdr.th_dport = htons(self->x_dst_port);
	self->thdr.th_seq = htonl(self->x_tx_seq);
 	self->thdr.th_ack = htonl(self->x_tx_ack);
	
	if(dlen == 0)
		self->thdr.psh = 0;

	self->thdr.th_sum = 0;
	self->pl = realloc(self->pl, dlen);
	memcpy(self->pl, data, dlen);
	self->plen = dlen;
	uint16_t cksum = cal_tcp_cksm(iphdr, self->thdr, data, dlen);
	self->thdr.th_sum = cksum;
		
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

