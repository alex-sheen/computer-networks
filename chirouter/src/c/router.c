/* CMSC 233000 - Project 3 - chirouter 
 * Edward Rose and Alex Sheen
 */
/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
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

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

#define ETHERNET_FRAME_ICMP_LENGTH 98

/* get_rtable_entry
 * desc:
 *  gets a table entry in the routing table based on given ip dst
 * parameters:
 *  chirouter_ctx_t *ctx -> chirouter context struct 
 *  uint32_t ip_dst -> destination ip we are comparing in rtable.
 * returns:
 *  a ptr to a routing table entry if found, 
 *  if not found, returns NULL. 
 */ 
chirouter_rtable_entry_t *get_rtable_entry(chirouter_ctx_t *ctx, uint32_t ip_dst)
{
    uint64_t longest_prefix = 0;
    chirouter_rtable_entry_t *rtable_entry = NULL;

    /* check each entry in routing table */
    for (int i = 0; i < ctx->num_rtable_entries; i++)
    {
        struct in_addr mask = ctx->routing_table[i].mask;
        struct in_addr ip_check = ctx->routing_table[i].dest;

        /* if match */
        if ((mask.s_addr & ip_check.s_addr)
            == (mask.s_addr & ip_dst))
        {
            /* update longest prefix */
            if (mask.s_addr >= longest_prefix)
            {
                chilog(DEBUG, "interface matched!!, SAVE");

                longest_prefix = mask.s_addr;
                rtable_entry = &ctx->routing_table[i];
            }
            else
            {
                chilog(DEBUG, "interface matched!!, DROP");
            }
        }

        /* try gateway if it exists */
        if (ctx->routing_table[i].gw.s_addr != 0)
        {
            chilog(DEBUG, "gateway exists, trying it...");
            ip_check = ctx->routing_table[i].gw;

            if ((mask.s_addr & ip_check.s_addr)
            == (mask.s_addr & ip_dst))
            {
                /* update longest prefix */
                if (mask.s_addr >= longest_prefix)
                {
                    chilog(DEBUG, "interface matched!!, SAVE");

                    longest_prefix = mask.s_addr;
                    rtable_entry = &ctx->routing_table[i];
                    if (ctx->routing_table[i].gw.s_addr != 0)
                    {
                        chilog(DEBUG, "RETURNING GATEWAY INTERFACE");
                        ip_check = ctx->routing_table[i].gw;
                    }
                }
                else
                {
                    chilog(DEBUG, "interface matched!!, DROP");
                }
            }
        }
    }
    return rtable_entry;
}


/* send_network_unreachable 
 * desc:
 *  sends a network unreachable frame
 * parameters:
 *  chirouter_ctx_t *ctx -> context struct for chirouter
 *  ethernet_frame_t *frame -> incoming frame
 * returns:
 *  0 - on success
 *  -1 - on failure */
int send_network_unreachable(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t* eth_hdr_frame = (ethhdr_t*) frame->raw;
    iphdr_t* ip_hdr_frame = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));

    chilog(INFO, "ICMPCODE_DEST_NET_UNREACHABLE");

    ethernet_frame_t *frame_msg = calloc(1, sizeof(ethernet_frame_t));

    frame_msg->length = sizeof(ethhdr_t) + sizeof(iphdr_t) 
                        + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8;

    frame_msg->raw = calloc(1, frame_msg->length);

    /* set Ethernet header - swap src and dst */
    chilog(DEBUG, "setting Ethernet header...");
    ethhdr_t* eth_hdr_msg = (ethhdr_t*) frame_msg->raw;
    eth_hdr_msg->type = htons(ETHERTYPE_IP);
    memcpy(eth_hdr_msg->dst, eth_hdr_frame->src, ETHER_ADDR_LEN);
    memcpy(eth_hdr_msg->src, frame->in_interface->mac, ETHER_ADDR_LEN);

    /* set IP header - TTL, swap src and dst */
    chilog(DEBUG, "setting IP header...");
    iphdr_t* ip_hdr_msg = (iphdr_t*) (frame_msg->raw + sizeof(ethhdr_t));
    memcpy(ip_hdr_msg, ip_hdr_frame, sizeof(iphdr_t));
    ip_hdr_msg->proto = IPPROTO_ICMP;

    ip_hdr_msg->len = htons(sizeof(iphdr_t) + ICMP_HDR_SIZE 
                      + sizeof(iphdr_t) + 8);

    ip_hdr_msg->ttl = DEFAULT_TTL;
    ip_hdr_msg->src = frame->in_interface->ip.s_addr;
    ip_hdr_msg->dst = ip_hdr_frame->src;
    chilog(DEBUG, "calculating IP cksum...");
    ip_hdr_msg->cksum = 0;
    ip_hdr_msg->cksum = cksum(ip_hdr_msg, sizeof(iphdr_t));

    /* Set ICMP header */
    icmp_packet_t* icmp_msg = (icmp_packet_t*)
            (frame_msg->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));

    icmp_msg->type = ICMPTYPE_DEST_UNREACHABLE;
    icmp_msg->code = ICMPCODE_DEST_NET_UNREACHABLE;

    /* Internet Header + 64 bits of Data Datagram */
    memcpy(&icmp_msg->dest_unreachable.payload, ip_hdr_frame, 
            sizeof(iphdr_t) + 8);

    icmp_msg->chksum = 0;
    icmp_msg->chksum = cksum(icmp_msg, ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

    chilog(DEBUG, "sending frame...");
    chilog_ip(DEBUG, ip_hdr_msg, LOG_OUTBOUND);
    chilog_icmp(DEBUG, icmp_msg, LOG_OUTBOUND);

    if (chirouter_send_frame(ctx, frame->in_interface, 
                            frame_msg->raw, frame_msg->length) == -1)
    {
        chilog(ERROR, "handle_IP_frame: fatal error when sending frame");
        return -1;
    } 

    return 0; 
}


/* handle_ARP_frame
 * desc:
 *  if an incoming frame is of type ARP, this function handles it
 * parameters:
 *  chirouter_ctx_t *ctx -> context struct for chirouter
 *  ethernet_frame_t *frame -> incoming frame
 * returns:
 *  0 - on success
 *  -1 - on failure */
int handle_ARP_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    chilog(INFO, "handle_ARP_frame");

    /* Accessing headers */
    ethhdr_t* hdr_frame = (ethhdr_t*) frame->raw;
    arp_packet_t* arp_frame = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));

    struct in_addr in_addr_test;
    in_addr_test.s_addr = arp_frame->tpa;
    chilog(DEBUG, "frame dst : %s =? %s : interface IP",  
                inet_ntoa(in_addr_test), 
                inet_ntoa(frame->in_interface->ip));

    chilog_arp(DEBUG, arp_frame, LOG_INBOUND);

    if(arp_frame->op == htons(ARP_OP_REPLY)){
        chilog(DEBUG, "received an ARP REPLY");
        struct in_addr arp_ip;
        arp_ip.s_addr = arp_frame->spa;
        pthread_mutex_lock(&ctx->lock_arp);
        chirouter_arp_cache_add(ctx, &arp_ip, arp_frame->sha);

        chirouter_pending_arp_req_t *pending_req = 
            chirouter_arp_pending_req_lookup(ctx, &arp_ip);

        withheld_frame_t *tmp = pending_req->withheld_frames;

        chirouter_arpcache_entry_t *found = 
            chirouter_arp_cache_lookup(ctx, &pending_req->ip);
        
        /* iterate through LL */
        while (tmp != NULL)
        {
            chilog(DEBUG, "chirouter_arp_process_pending_req: forwards frame");
            if (chirouter_forward_frame(ctx, tmp->frame, 
                                        pending_req->out_interface, 
                                        found->mac) == -1)
            {
                chilog(ERROR, "chirouter_forward_frame: failed to forward.");
            }

            tmp = tmp->next;
        }

        if (chirouter_arp_pending_req_free_frames(pending_req) == 1)
        {
            chilog(ERROR, "chirouter_arp_pending_req_free_frames: failed");
        }

        DL_DELETE(ctx->pending_arp_reqs, pending_req);

        pthread_mutex_unlock(&ctx->lock_arp);
        return 0;
    }

    /* send ARP reply if IP dest == interface's IP addr and type is REQUEST */
    if (arp_frame->tpa == frame->in_interface->ip.s_addr && 
        arp_frame->op == htons(ARP_OP_REQUEST))
    {
        chilog(DEBUG, "received an ARP REQUEST");
        chilog(INFO, "creating ARP reply...");

        /* set Ethernet header */
        ethernet_frame_t *frame_msg = calloc(1, sizeof(ethernet_frame_t));
        frame_msg->length = frame->length;
        frame_msg->raw = calloc(1, sizeof(frame->length));

        chilog(DEBUG, "setting ARP Ethernet header...");
        ethhdr_t* hdr_msg = (ethhdr_t*) frame_msg->raw;
        hdr_msg->type = htons(ETHERTYPE_ARP);
        memcpy(hdr_msg->dst, hdr_frame->src, ETHER_ADDR_LEN);
        memcpy(hdr_msg->src, frame->in_interface->mac, ETHER_ADDR_LEN);
        
        /* set ARP packet */
        chilog(DEBUG, "setting ARP packet...");
        arp_packet_t* arp_msg = (arp_packet_t*) 
                                (frame_msg->raw + sizeof(ethhdr_t));

        memcpy(arp_msg, arp_frame, sizeof(arp_packet_t));

        arp_msg->op = htons(ARP_OP_REPLY);

        /* source info */
        arp_msg->spa = arp_frame->tpa;
        memcpy(arp_msg->sha, frame->in_interface->mac, ETHER_ADDR_LEN);

        /* target info */
        arp_msg->tpa = arp_frame->spa;
        memcpy(arp_msg->tha, arp_frame->sha, ETHER_ADDR_LEN);

        chilog(DEBUG, "sending ARP reply...");
        chilog_arp(DEBUG, arp_msg, LOG_OUTBOUND);

        if (chirouter_send_frame(ctx, frame->in_interface, 
                                 frame_msg->raw, frame->length) == -1)
        {
            chilog(ERROR, "handle_ARP_frame: fatal error when sending frame");
            return -1;
        }
    }
    
    return 0;
}


/* handle_to_me 
 * desc:
 *  handles a frame that is recognized (no need to forward or request).
 * parameters:
 *  chirouter_ctx_t *ctx -> chirouter context struct 
 *  ethernet_frame_t *frame -> incoming frame 
 * returns:
 *  0 - on success 
 *  -1 - on failure
 */ 
int handle_to_me(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    chilog(INFO, "handle_IP_frame: ICMP packet");

    ethhdr_t* eth_hdr_frame = (ethhdr_t*) frame->raw;
    iphdr_t* ip_hdr_frame = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));

    /* set ICMP packet */
    struct in_addr tmp;
    for (int i = 0; i < ctx->num_interfaces; i++)
    {
        tmp.s_addr = ip_hdr_frame->dst;
        /* find interface that matches frame dest */
        if (ctx->interfaces[i].ip.s_addr == ip_hdr_frame->dst)
        {    
            /* does DST IP match IP of interface? */
            if (ip_hdr_frame->dst == frame->in_interface->ip.s_addr) 
            {
                /* TCP / UDP - ICMPCODE_DEST_PORT_UNREACHABLE */
                if (ip_hdr_frame->proto == IPPROTO_TCP || 
                    ip_hdr_frame->proto == IPPROTO_UDP)
                {
                    chilog(INFO, "IPPROTO_TCP or IPPROTO_UDP");
                    chilog(INFO, "ICMPTYPE_DEST_UNREACHABLE");

                    ethernet_frame_t *frame_msg = 
                                        calloc(1, sizeof(ethernet_frame_t));

                    frame_msg->length = sizeof(ethhdr_t) + sizeof(iphdr_t) 
                                        + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8;

                    frame_msg->raw = calloc(1, frame_msg->length);

                    /* set Ethernet header - swap src and dst */
                    chilog(DEBUG, "setting Ethernet header...");
                    ethhdr_t* eth_hdr_msg = (ethhdr_t*) frame_msg->raw;
                    eth_hdr_msg->type = htons(ETHERTYPE_IP);

                    memcpy(eth_hdr_msg->dst, eth_hdr_frame->src, 
                            ETHER_ADDR_LEN);

                    memcpy(eth_hdr_msg->src, frame->in_interface->mac, 
                            ETHER_ADDR_LEN);

                    /* set IP header - TTL, swap src and dst */
                    chilog(DEBUG, "setting IP header...");
                    iphdr_t* ip_hdr_msg = (iphdr_t*) 
                                          (frame_msg->raw + sizeof(ethhdr_t));

                    memcpy(ip_hdr_msg, ip_hdr_frame, sizeof(iphdr_t));
                    ip_hdr_msg->proto = IPPROTO_ICMP;

                    ip_hdr_msg->len = htons(sizeof(iphdr_t) 
                                      + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                    ip_hdr_msg->ttl = DEFAULT_TTL;
                    ip_hdr_msg->src = frame->in_interface->ip.s_addr;
                    ip_hdr_msg->dst = ip_hdr_frame->src;
                    chilog(DEBUG, "calculating IP cksum...");
                    ip_hdr_msg->cksum = 0;
                    ip_hdr_msg->cksum = cksum(ip_hdr_msg, sizeof(iphdr_t));

                    /* Set ICMP */
                    icmp_packet_t* icmp_msg = (icmp_packet_t*) 
                        (frame_msg->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));

                    icmp_msg->type = ICMPTYPE_DEST_UNREACHABLE;
                    icmp_msg->code = ICMPCODE_DEST_PORT_UNREACHABLE;

                    /* Internet Header + 64 bits of Data Datagram */
                    memcpy(&icmp_msg->dest_unreachable.payload, 
                            ip_hdr_frame, 
                            sizeof(iphdr_t) + 8);

                    icmp_msg->chksum = 0;
                    icmp_msg->chksum = cksum(icmp_msg, 
                                        ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                    chilog(DEBUG, "sending frame...");
                    chilog_ip(DEBUG, ip_hdr_msg, LOG_OUTBOUND);
                    chilog_icmp(DEBUG, icmp_msg, LOG_OUTBOUND);

                    if (chirouter_send_frame(ctx, frame->in_interface, 
                                             frame_msg->raw, 
                                             frame_msg->length) == -1)
                    {
                        chilog(ERROR, "handle_IP_frame: fatal err frame sent");
                        return -1;
                    }   
                }

                /* ICMPTYPE_TIME_EXCEEDED */
                else if (ip_hdr_frame->ttl <= 1)
                {
                    chilog(INFO, "ICMPTYPE_TIME_EXCEEDED");

                    ethernet_frame_t *frame_msg = 
                                            calloc(1, sizeof(ethernet_frame_t));

                    frame_msg->length = sizeof(ethhdr_t) + sizeof(iphdr_t) 
                                        + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8;

                    frame_msg->raw = calloc(1, frame_msg->length);

                    /* Set Ethernet header - swap src and dst. */
                    chilog(DEBUG, "setting Ethernet header...");
                    ethhdr_t* eth_hdr_msg = (ethhdr_t*) frame_msg->raw;
                    eth_hdr_msg->type = htons(ETHERTYPE_IP);

                    memcpy(eth_hdr_msg->dst, eth_hdr_frame->src,
                           ETHER_ADDR_LEN);

                    memcpy(eth_hdr_msg->src, frame->in_interface->mac, 
                           ETHER_ADDR_LEN);

                    /* Set IP header - TTL, swap src and dst. */
                    chilog(DEBUG, "setting IP header...");
                    iphdr_t* ip_hdr_msg = (iphdr_t*) 
                                          (frame_msg->raw + sizeof(ethhdr_t));

                    memcpy(ip_hdr_msg, ip_hdr_frame, sizeof(iphdr_t));
                    ip_hdr_msg->len = htons(sizeof(iphdr_t) 
                                      + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                    ip_hdr_msg->ttl = DEFAULT_TTL;
                    ip_hdr_msg->src = frame->in_interface->ip.s_addr;
                    ip_hdr_msg->dst = ip_hdr_frame->src;
                    chilog(DEBUG, "calculating IP cksum...");
                    ip_hdr_msg->cksum = 0;
                    ip_hdr_msg->cksum = cksum(ip_hdr_msg, sizeof(iphdr_t));

                    /* Set ICMP */
                    icmp_packet_t* icmp_msg = (icmp_packet_t*) 
                        (frame_msg->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));

                    icmp_msg->type = ICMPTYPE_TIME_EXCEEDED;
                    icmp_msg->code = 0;

                    /* Internet Header + 64 bits of Data Datagram */
                    memcpy(&icmp_msg->dest_unreachable.payload, 
                            ip_hdr_frame, sizeof(iphdr_t) + 8);

                    icmp_msg->chksum = 0;
                    icmp_msg->chksum = cksum(icmp_msg, 
                            ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                    chilog(DEBUG, "sending frame...");
                    chilog_ip(DEBUG, ip_hdr_msg, LOG_OUTBOUND);
                    chilog_icmp(DEBUG, icmp_msg, LOG_OUTBOUND);

                    if (chirouter_send_frame(ctx, frame->in_interface, 
                                             frame_msg->raw, 
                                             frame_msg->length) == -1)
                    {
                        chilog(ERROR, "handle_IP_frame: fatal err in frame");
                        return -1;
                    }
                }
                
                /* ICMPTYPE_ECHO_REPLY */
                else if (ip_hdr_frame->proto == IPPROTO_ICMP)
                {
                    chilog(INFO, "IPPROTO_ICMP");
                    icmp_packet_t* icmp_frame = (icmp_packet_t*) 
                            (frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
                    
                    /* ICMPTYPE_ECHO_REPLY */
                    if (icmp_frame->type == ICMPTYPE_ECHO_REQUEST)
                    {
                        /* Set Ethernet header - swap src and dst. */
                        chilog(DEBUG, "setting Ethernet header...");

                        memcpy(eth_hdr_frame->dst, eth_hdr_frame->src, 
                                ETHER_ADDR_LEN);

                        memcpy(eth_hdr_frame->src, frame->in_interface->mac, 
                                ETHER_ADDR_LEN);

                        /* Set IP header - TTL, swap src and dst. */
                        chilog(DEBUG, "setting IP header...");
                        ip_hdr_frame->ttl = DEFAULT_TTL;
                        ip_hdr_frame->dst = ip_hdr_frame->src;
                        ip_hdr_frame->src = frame->in_interface->ip.s_addr;
                        chilog(DEBUG, "calculating IP cksum...");
                        ip_hdr_frame->cksum = 0;
                        ip_hdr_frame->cksum = cksum(ip_hdr_frame, 
                                                    sizeof(iphdr_t));
                        
                        chilog(INFO, "ICMPTYPE_ECHO_REPLY");
                        icmp_frame->type = ICMPTYPE_ECHO_REPLY;

                        uint64_t frame_icmp_payload_length = frame->length 
                                                            - sizeof(ethhdr_t) 
                                                            - sizeof(iphdr_t);
                        icmp_frame->chksum = 0;
                        icmp_frame->chksum = cksum(icmp_frame, 
                                                   frame_icmp_payload_length);

                        chilog(DEBUG, "sending frame...");
                        chilog_ip(DEBUG, ip_hdr_frame, LOG_OUTBOUND);
                        chilog_icmp(DEBUG, icmp_frame, LOG_OUTBOUND);

                        if (chirouter_send_frame(ctx, frame->in_interface, 
                                                 frame->raw, 
                                                 frame->length) == -1)
                        {
                            chilog(ERROR, "handle_IP_frame: fatal err frame");
                            return -1;
                        }
                    }
                }
            }

            /* ICMPTYPE_DEST_HOST_UNREACHABLE */
            else
            {
                chilog(INFO, "ICMPTYPE_DEST_HOST_UNREACHABLE");

                ethernet_frame_t *frame_msg = calloc(1, 
                                              sizeof(ethernet_frame_t));
                
                frame_msg->length = sizeof(ethhdr_t) + sizeof(iphdr_t) 
                                    + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8;

                frame_msg->raw = calloc(1, frame_msg->length);

                /* set Ethernet header - swap src and dst */
                chilog(DEBUG, "setting Ethernet header...");
                ethhdr_t* eth_hdr_msg = (ethhdr_t*) frame_msg->raw;
                eth_hdr_msg->type = htons(ETHERTYPE_IP);
                memcpy(eth_hdr_msg->dst, eth_hdr_frame->src, ETHER_ADDR_LEN);

                memcpy(eth_hdr_msg->src, frame->in_interface->mac, 
                       ETHER_ADDR_LEN);

                /* set IP header - TTL, swap src and dst */
                chilog(DEBUG, "setting IP header...");
                iphdr_t* ip_hdr_msg = (iphdr_t*) 
                                      (frame_msg->raw + sizeof(ethhdr_t));
                
                memcpy(ip_hdr_msg, ip_hdr_frame, sizeof(iphdr_t));
                ip_hdr_msg->len = htons(sizeof(iphdr_t) 
                                  + ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                ip_hdr_msg->ttl = DEFAULT_TTL;
                ip_hdr_msg->src = frame->in_interface->ip.s_addr;
                ip_hdr_msg->dst = ip_hdr_frame->src;
                chilog(DEBUG, "calculating IP cksum...");
                ip_hdr_msg->cksum = 0;
                ip_hdr_msg->cksum = cksum(ip_hdr_msg, sizeof(iphdr_t));

                /* Set ICMP Packet */
                icmp_packet_t* icmp_msg = (icmp_packet_t*) 
                        (frame_msg->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
                
                icmp_msg->type = ICMPTYPE_DEST_UNREACHABLE;
                icmp_msg->code = ICMPCODE_DEST_HOST_UNREACHABLE;

                /* Internet Header + 64 bits of Data Datagram */
                memcpy(&icmp_msg->dest_unreachable.payload, ip_hdr_frame, 
                        sizeof(iphdr_t) + 8);

                icmp_msg->chksum = 0;
                icmp_msg->chksum = cksum(icmp_msg, 
                                        ICMP_HDR_SIZE + sizeof(iphdr_t) + 8);

                chilog(DEBUG, "sending frame...");
                chilog_ip(DEBUG, ip_hdr_msg, LOG_OUTBOUND);
                chilog_icmp(DEBUG, icmp_msg, LOG_OUTBOUND);

                if (chirouter_send_frame(ctx, frame->in_interface, 
                                         frame_msg->raw, 
                                         frame_msg->length) == -1)
                {
                    chilog(ERROR, "handle_IP_frame: fatal err frame sent");
                    return -1;
                }
            }
        }
    }
    return 0;
}


/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    chilog(INFO, "\n\n\n\n");
    chilog(INFO, "chirouter_process_ethernet_frame: received frame...");

    /* Accessing headers */
    ethhdr_t* hdr_frame = (ethhdr_t*) frame->raw;
    iphdr_t* ip_hdr_frame = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    arp_packet_t* arp_frame = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));

    /* Handle ARP frame. */
    if (ntohs(hdr_frame->type) == ETHERTYPE_ARP)
    {
        chilog(INFO, "is an ARP frame");
        return handle_ARP_frame(ctx, frame);
    }

    /* Handle IP frame. */
    else if (frame->in_interface->ip.s_addr == ip_hdr_frame->dst)
    {
        chilog(INFO, "is an IP frame, directed to me");
        return handle_to_me(ctx, frame);
    }

    /* Forward datagram to the destination. */
    chilog(INFO, "is an IP frame, not directed to me");
    chilog(DEBUG, "dst MAC %u : %u interface MAC", hdr_frame->dst, 
            frame->in_interface->mac);
    chilog(DEBUG, "dst IP %u : %u interface IP", ip_hdr_frame->dst, 
            frame->in_interface->ip.s_addr);

    
    chilog(DEBUG, "checking rtable... for %u", ip_hdr_frame->dst);

    chirouter_rtable_entry_t *rtable_entry = get_rtable_entry(ctx, 
                                                            ip_hdr_frame->dst);
    
    /* If IP doesn't match anything in routing table. */
    if (rtable_entry == NULL) 
    {
        chilog(ERROR, 
        "chirouter_process_ethernet_frame - didn't find IP in routing table.");

        return send_network_unreachable(ctx, frame);
    }

    /* The IP matched an entry. */
    chirouter_interface_t *interface = rtable_entry->interface;
    
    /* Check ARP cache. */
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_hdr_frame->dst;

    /* Use gateway IP? */
    if (rtable_entry->gw.s_addr != 0)
    {
        chilog(DEBUG, "IMPORTANT: using gateway");
        ip_addr.s_addr = rtable_entry->gw.s_addr;
    }

    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_arpcache_entry_t *found = 
                        chirouter_arp_cache_lookup(ctx, &ip_addr);

    /* found entry in arp cache, forward it now */
    if (found != NULL ){ 
        chilog(INFO, "MAC dest aleady in ARP cache, sending now...");

        if (chirouter_forward_frame(ctx, frame, interface, found->mac) == 1){
            pthread_mutex_unlock(&ctx->lock_arp);
            chilog(ERROR, 
            "chirouter_process_ethernet_frame - forwarding frame failed.");
            return 1;
        } else {
            pthread_mutex_unlock(&ctx->lock_arp);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock_arp);
    chilog(INFO, "MAC dest not in ARP cache");

    /* ARP request already sent out */
    pthread_mutex_lock(&ctx->lock_arp);
    chirouter_pending_arp_req_t *pending_arp_req = 
                        chirouter_arp_pending_req_lookup(ctx, &ip_addr);

    /* Check if already in arp cache. */
    if (pending_arp_req != NULL)
    {
        chilog(INFO, "  already in pending arp cache");
        /* append frame to withheld frames */
        if (chirouter_arp_pending_req_add_frame(ctx, 
                                                pending_arp_req, frame) == 1)
        {
            return 1;
        }
        pthread_mutex_unlock(&ctx->lock_arp);
        return 0;
    }

    /* Create new pending ARP request. */
    else
    {
        chilog(INFO, "  not in pending arp cache, adding it");

        /* Create new pending arp request with sent ARP requests equal to 1.
         * Also, append the frame. */
        chirouter_pending_arp_req_t *pending_arp_req = 
                        chirouter_arp_pending_req_add(ctx, &ip_addr, interface);

        /* First time sending. Times sent will be 1. */
        pending_arp_req->times_sent = 1;
        pending_arp_req->last_sent = time(NULL);

        if (chirouter_arp_pending_req_add_frame(ctx, 
                                                pending_arp_req, frame) == 1)
        {
            return 1;
        }

        pthread_mutex_unlock(&ctx->lock_arp);
        return send_arp_request(ctx, interface, ip_addr.s_addr);
    }
}



