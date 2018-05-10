/*
 * transport.c 
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include "time.h"

// globals
static const unsigned int WINDOW_SIZE = 3072;
static const unsigned int MSS = 536;

// states
enum { 
    CSTATE_ESTABLISHED,
    SENT_SYN,
    RECV_SYN_ACK,
    RECV_SYN,
    RECV_ACK,
    SENT_ACK,
    SENT_SYN_ACK,
    SENT_FIN,
    CLOSED
};   


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
// funtions used
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags);
bool get_packet(mysocket_t sd, context_t *ctx, uint8_t flags);

bool send_syn(mysocket_t sd, context_t *ctx);
bool get_syn_ack(myscket_t sd, context_t *ctx);
bool send_ack(mysocket_t sd, context_t *ctx);
bool get_syn(myscket_t sd, context_t *ctx);
bool send_syn_ack(mysocket_t sd, context_t *ctx);
bool get_ack(myscket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if(is_active) {
        // send SYN packet
        if(!send_packet(sd, ctx, TH_SYN))
            return; // unable to send so exit out
        ctx->connection_state = SENT_SYN;

        // then we need to wait for the ack
        if(!get_packet(sd, ctx, (TH_SYN | TH_ACK)))
            return; // did not get syn ack        
        ctx->connection_state = RECV_SYN_ACK;

        // finally ack the syn ack
        if(!send_packet(sd, ctx, TH_ACK))
            return;
        ctx->connection_state = SENT_ACK;

    } else {
        // wait for SYN packet
        if(!get_packet(sd, ctx, TH_SYN))
            return;
        ctx->connection_state = RECV_SYN;

        if(!send_packet(sd, ctx, (TH_SYN | TH_ACK)))
            return;
        ctx->connection_state = SENT_SYN_ACK;

        if(!get_packet(sd, ctx, TH_ACK))
            return;
        ctx->connection_state = RECV_ACK;
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

// send a packet
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags) {
    // create the packet
    STCPHeader* packet = (STPCHeader*) malloc(sizeof(STCPHeader));
    packet->th_seq = htonl(ctx->seq_num++);
    packet->th_ack = htonl(ctx->rec_seq_num+1);
    packet->th_flags = flags;
    packet->th_win = htons(WINDOW_SIZE);
    packet->th_off = htonl(5); // not using optional field

    // send the packet    
    if((ssize_t bytes = stcp_network_send(sd, packet, sizeof(STCPHeader), NULL)) > 0) {
        // free the memory
        free(packet);
        return true;
    } else {
        // there was an error sending
        errno = ECONNREFUSED;
        // free memory
        free(packet);
        free(ctx);
        return false;
    }    
}

// funtion to wait for a packet
bool get_packet(myscket_t sd, context_t *ctx, uint8_t flags) {
    // create the buffer to receive header
    char buffer[sizeof(STCPHeader)];

    // wait for an event in our socket
    stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    // then recv the bytes
    if((ssize_t bytes_recvd = stcp_network_recv(sd, buffer, MSS)) < sizeof(STCPHeader)) {
        // we did not recieve all the bytes that we should have gotten
        errno = ECONNREFUSED;
        // free memory we dont need anymore
        free(ctx);
        return false;
    }

    // get packet info from buffer
    STCPHeader *packet = (STCPHeader*)buffer;

    // make sure it is a syn-ack packet
    if(packet->th_flags != flags) {
        // we did not recieve the right flags
        errno = ECONNREFUSED;
        // free memory we dont need anymore
        free(ctx);
        return false;
    }

    // get the rec window size and seq num from receiver
    ctx->rec_wind_size = ntohs(packet->th_win);
    if(ctx->rec_wind_size == 0)
        ctx->rec_wind_size = 1; // for flow control - if 0 try sending 1 byte

    ctx->rec_seq_num = ntohl(packet->th_seq);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->rec_seq_num = 0;

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    // set to rand
    srand(time(0));
    ctx->initial_sequence_num = rand() % 500;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



