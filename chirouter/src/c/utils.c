/* CMSC 233000 - Project 3 - chirouter 
 * Edward Rose and Alex Sheen
 */
/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains miscellaneous helper functions.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 *
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "protocols/ethernet.h"
#include "utils.h"

/* See utils.h */
uint16_t cksum (const void *_data, int len)
{
      const uint8_t *data = _data;
      uint32_t sum;

      for (sum = 0;len >= 2; data += 2, len -= 2)
      {
        sum += data[0] << 8 | data[1];
      }

      if (len > 0)
      {
        sum += data[0] << 8;
      }

      while (sum > 0xffff)
      {
        sum = (sum >> 16) + (sum & 0xffff);
      }

      sum = htons (~sum);

      return sum ? sum : 0xffff;
}

/* See utils.h */
bool ethernet_addr_is_equal(uint8_t *addr1, uint8_t *addr2)
{
    for (int i=0; i<ETHER_ADDR_LEN; i++)
    {
        if(addr1[i] != addr2[i])
            return false;
    }
    return true;
}

/* See utils.h */
int chirouter_forward_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame, chirouter_interface_t *interface, uint8_t *mac_dst){

    if (frame == NULL){
        chilog(WARNING, "chirouter_forward_frame - Frame was NULL.");
        return 1;
    }
    
    /* Grab header locations of inbound frame */
    ethhdr_t* eth_hdr_frame = (ethhdr_t*) frame->raw;
    iphdr_t* ip_hdr_frame = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));

    if (ip_hdr_frame->ttl <= 1)
    {
        chilog(INFO, "ICMPTYPE_TIME_EXCEEDED");
        
        /* Allocated data for frame. */
        ethernet_frame_t *frame_msg = calloc(1, sizeof(ethernet_frame_t));
        frame_msg->length = sizeof(ethhdr_t) + sizeof(iphdr_t) + ICMP_HDR_SIZE 
                            + sizeof(iphdr_t) + 8;
        frame_msg->raw = calloc(1, frame_msg->length);

        /* set Ethernet header - swap src and dst */
        chilog(DEBUG, "setting Ethernet header...");
        ethhdr_t* eth_hdr_msg = (ethhdr_t*) frame_msg->raw;
        eth_hdr_msg->type = htons(ETHERTYPE_IP);
        memcpy(eth_hdr_msg->dst, eth_hdr_frame->src, ETHER_ADDR_LEN);
        memcpy(eth_hdr_msg->src, frame->in_interface->mac, ETHER_ADDR_LEN);

        /* set IP header - Set TTL, len and protocol, 
         * swap src and dst, recompute checksum. */
        chilog(DEBUG, "setting IP header...");
        iphdr_t* ip_hdr_msg = (iphdr_t*) (frame_msg->raw + sizeof(ethhdr_t));
        memcpy(ip_hdr_msg, ip_hdr_frame, sizeof(iphdr_t));

        ip_hdr_msg->len = htons(sizeof(iphdr_t) + ICMP_HDR_SIZE 
                                + sizeof(iphdr_t) + 8);

        ip_hdr_msg->proto = IPPROTO_ICMP;
        ip_hdr_msg->ttl = DEFAULT_TTL;
        ip_hdr_msg->src = frame->in_interface->ip.s_addr;
        ip_hdr_msg->dst = ip_hdr_frame->src;
        chilog(DEBUG, "calculating IP cksum...");
        ip_hdr_msg->cksum = 0;
        ip_hdr_msg->cksum = cksum(ip_hdr_msg, sizeof(iphdr_t));

        /* ICMP header - Set payload and recompute checksum. */
        icmp_packet_t* icmp_msg = (icmp_packet_t*) 
                          (frame_msg->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));

        icmp_msg->type = ICMPTYPE_TIME_EXCEEDED;
        icmp_msg->code = 0;
        /* Internet Header + 64 bits of Data Datagram */
        memcpy(&icmp_msg->dest_unreachable.payload, ip_hdr_frame, 
                sizeof(iphdr_t) + 8);

        icmp_msg->chksum = 0;
        icmp_msg->chksum = cksum(icmp_msg, ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

        chilog(DEBUG, "sending frame...");
        chilog_ip(DEBUG, ip_hdr_msg, LOG_OUTBOUND);
        chilog_icmp(DEBUG, icmp_msg, LOG_OUTBOUND);

        if (chirouter_send_frame(ctx, frame->in_interface, frame_msg->raw, 
                                 frame_msg->length) == -1)
        {
            chilog(ERROR, "handle_IP_frame: fatal error when sending frame");
            return -1;
        }
        return 0;
    }

    /* TTL was not <= to 1 */

    /* Set Ethernet Header - swap src and dst. */
    ethhdr_t* eth_hdr = (ethhdr_t*) frame->raw;
    memcpy(eth_hdr->dst, mac_dst, ETHER_ADDR_LEN);
    memcpy(eth_hdr->src, interface->mac, ETHER_ADDR_LEN);
    
    chilog(INFO, "chirouter_forward_frame - sending frame to client");

    /* If frame is of type ARP, we don't need an IP header. */
    if (ntohs(eth_hdr->type) == ETHERTYPE_ARP)
    {
      arp_packet_t* arp_frame = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
      chilog_arp(DEBUG, arp_frame, LOG_OUTBOUND);
    }

    else
    {
       /* set IP header - Set TTL, swap src and dst. */
      iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
      ip_hdr->ttl -= 1; 
      ip_hdr->cksum = 0;
      ip_hdr->cksum = cksum(ip_hdr, sizeof(iphdr_t));
    }

    if (chirouter_send_frame(ctx, interface, frame->raw, frame->length) == 1){
        chilog(ERROR, "chirouter_forward_frame - failed to send client");
        return 1;
    }

    return 0;
}

/* See utils.h */
int send_arp_request(chirouter_ctx_t *ctx, chirouter_interface_t *interface, uint32_t ip_dst)
{
    /* create arp request for server1 */
    chilog(INFO, "creating ARP request...");

    /* Allocated Data for Frame */
    ethernet_frame_t *frame_msg = calloc(1, sizeof(ethernet_frame_t));
    frame_msg->length = sizeof(ethhdr_t) + sizeof(arp_packet_t);
    frame_msg->raw = calloc(1, sizeof(frame_msg->length));

    /* set Ethernet header */
    chilog(DEBUG, "setting ARP Ethernet header...");
    ethhdr_t* hdr_msg = (ethhdr_t*) frame_msg->raw;
    hdr_msg->type = htons(ETHERTYPE_ARP);

    memcpy(hdr_msg->src, interface->mac, ETHER_ADDR_LEN);
    memset(hdr_msg->dst, 0xFF, ETHER_ADDR_LEN);
    
    /* Create ARP packet */
    chilog(DEBUG, "setting ARP packet..."); 
    arp_packet_t* arp_msg = (arp_packet_t*) (frame_msg->raw + sizeof(ethhdr_t));

    arp_msg->hrd = htons(ARP_HRD_ETHERNET);
    arp_msg->pro = htons(ETHERTYPE_IP);
    arp_msg->hln = ETHER_ADDR_LEN;
    arp_msg->pln = IPV4_ADDR_LEN;
    arp_msg->op = htons(ARP_OP_REQUEST);

    /* source information */
    memcpy(arp_msg->sha, interface->mac, ETHER_ADDR_LEN);
    arp_msg->spa = interface->ip.s_addr;

    /* target information */
    memset(arp_msg->tha, 0, ETHER_ADDR_LEN);
    arp_msg->tpa = ip_dst;
    
    chilog(DEBUG, "sending ARP request...");
    if (chirouter_send_frame(ctx, interface, frame_msg->raw, 
                             frame_msg->length) == -1)
    {
        chilog(ERROR, "handle_IP_frame: fatal error when sending frame");
        return -1;
    }

    chilog_arp(DEBUG, arp_msg, LOG_OUTBOUND);
    return 0;
}
