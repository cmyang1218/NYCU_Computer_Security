#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
	int sock_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	struct sadb_msg msg;
	char *recv_buff = (char *)calloc(1024, sizeof(char));
	if(sock_fd < 0) 
		perror("Socket()");

	bzero(&msg, sizeof(msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_DUMP;
	msg.sadb_msg_satype = type;
	msg.sadb_msg_len = sizeof(msg) / 8;
	msg.sadb_msg_pid = getpid();

	write(sock_fd, &msg, sizeof(msg));
	ssize_t rd_sz = read(sock_fd, recv_buff, 1024);

	struct sadb_msg *recv_msg = (struct sadb_msg *)recv_buff;
	if(rd_sz != recv_msg->sadb_msg_len * 8){
		fprintf(stderr, "Sadb msg_len not matched\n");
	}
	if(recv_msg->sadb_msg_version != PF_KEY_V2){
		fprintf(stderr, "Sadb msg_version not matched\n");
	}
	if(rd_sz == sizeof(struct sadb_msg)){
		printf("No extension\n");
	}else{
		rd_sz -= sizeof(struct sadb_msg);
		recv_buff += sizeof(struct sadb_msg);
		
		while(rd_sz > 0){
			struct sadb_ext *recv_ext = (struct sadb_ext *)recv_buff;
			if(recv_ext->sadb_ext_type == SADB_EXT_KEY_AUTH){
				struct sadb_key *recv_key = (struct sadb_key *)recv_buff;
				memcpy(key, recv_buff + sizeof(struct sadb_key), recv_key->sadb_key_bits / 8);
				rd_sz -= (recv_ext->sadb_ext_len * 8);
				rd_sz -= (recv_key->sadb_key_bits / 8);
			}else{
				rd_sz -= (recv_ext->sadb_ext_len * 8);
				recv_buff += (recv_ext->sadb_ext_len * 8);
			}
		}
	}
	return;
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    int pad_len = -(self->plen+2);
	while(pad_len < 0) pad_len += 4;
	self->pad = (uint8_t *)realloc(self->pad, pad_len);
	bzero(self->pad, pad_len);
	uint8_t padding = 1;
	for(int i = 0; i < pad_len; i++){
		memcpy(self->pad + i, &padding, 1);
		padding++;
	}
	self->tlr.pad_len = pad_len;
	return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
	memcpy(buff, &self->hdr, sizeof(EspHeader));

	memcpy(buff+sizeof(EspHeader), self->pl, self->plen);
	memcpy(buff+sizeof(EspHeader)+self->plen, self->pad, self->tlr.pad_len);
	memcpy(buff+sizeof(EspHeader)+self->plen+self->tlr.pad_len, &self->tlr, sizeof(EspTrailer));
	nb += (sizeof(EspHeader) + self->plen + self->tlr.pad_len + sizeof(EspTrailer));
    
	ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
	EspHeader *esp_hdr = (EspHeader *)esp_pkt;
	self->hdr.spi = esp_hdr->spi;
	self->hdr.seq = esp_hdr->seq;
	
	EspTrailer *esp_tlr = (EspTrailer *)(esp_pkt + esp_len - sizeof(EspTrailer) - HMAC96AUTHLEN);
	self->tlr.pad_len = esp_tlr->pad_len;
	self->tlr.nxt = esp_tlr->nxt;
	
	uint8_t *auth = esp_pkt + esp_len - HMAC96AUTHLEN;
	memcpy(self->auth, auth, HMAC96AUTHLEN);
	self->authlen = HMAC96AUTHLEN;

	self->plen = esp_len - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN - esp_tlr->pad_len;
	return esp_pkt + sizeof(EspHeader);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
	esp_hdr_rec.seq += 1;
	self->hdr.spi = esp_hdr_rec.spi;
	self->hdr.seq = htonl(esp_hdr_rec.seq);
	self->tlr.nxt = p;
	return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
