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
#include <sys/time.h>

// globals
static const unsigned int WINDOW_SIZE = 3072;
static const unsigned int MSS = 536;

// states
enum { 
    CSTATE_ESTABLISHED,
    SENT_FIN,
    CLOSED
};   

/* this structure is global to a mysocket descriptor */
typedef struct context_t
{
    bool_t done;    /* TRUE once connection is closed */
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
	unsigned int seq_num;
	unsigned int rec_seq_num;
	unsigned int rec_win;
} ctx;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
// added funtions
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, char* data, ssize_t length);
bool get_packet(mysocket_t sd, context_t *ctx, uint8_t flags);
bool app_close_event(mysocket_t sd, context_t* ctx);
bool network_data_event(mysocket_t sd, context_t* ctx);
bool app_data_event(mysocket_t sd, context_t *ctx);


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

    if(is_active) {
        // send SYN packet
        if(!send_packet(sd, ctx, TH_SYN, NULL, 0))
            return; // unable to send so exit out

        // then we need to wait for the ack
        if(!get_packet(sd, ctx, (TH_SYN | TH_ACK)))
            return; // did not get syn ack        

        // finally ack the syn ack
        if(!send_packet(sd, ctx, TH_ACK, NULL, 0))
            return;

    } else {
        // wait for SYN packet
        if(!get_packet(sd, ctx, TH_SYN))
            return;

        // send a syn ack
        if(!send_packet(sd, ctx, (TH_SYN | TH_ACK), NULL, 0))
            return;

        // wait for ack
        if(!get_packet(sd, ctx, TH_ACK))
            return;
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

// send a packet
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, char* data, ssize_t length) {
    // create the packet
    STCPHeader* packet = (STCPHeader*) malloc(sizeof(STCPHeader) + length);
    packet->th_seq = htonl(ctx->seq_num++);
    packet->th_ack = htonl(ctx->rec_seq_num+1);
    packet->th_flags = flags;
    packet->th_win = htons(WINDOW_SIZE);
    packet->th_off = htonl(5); // not using optional field

    if(length > 0) 
        memcpy((char*)packet + sizeof(STCPHeader), data, length);

    // send the packet    
    if(stcp_network_send(sd, packet, sizeof(STCPHeader)+length, NULL) == (signed)sizeof(STCPHeader)+length) {
        // free the memory
        free(packet);
        return true;
    } else {
        // there was an error sending
        errno = ECONNREFUSED;
        // free memory
        free(packet);
        free(ctx);
        stcp_unblock_application(sd);
        return false;
    }    
}

// funtion to wait for a packet
bool get_packet(mysocket_t sd, context_t *ctx, uint8_t flags) {
    // create the buffer to receive header
    char buffer[sizeof(STCPHeader)];

    // wait for an event in our socket
    stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    // then recv the bytes
    if(stcp_network_recv(sd, buffer, MSS) < (signed)sizeof(STCPHeader)) {
        // we did not recieve all the bytes that we should have gotten
        errno = ECONNREFUSED;        
        // free memory we dont need anymore
        free(ctx);
        //stcp_unblock_application(sd);
        return false;
    }

    // get packet info from buffer
    STCPHeader *packet = (STCPHeader*)buffer;

    // make sure it is correct packet
    if(packet->th_flags != flags) {
        // we did not recieve the right flags
        errno = ECONNREFUSED;
        // free memory we dont need anymore
        free(ctx);
        //stcp_unblock_application(sd);
        return false;
    }

    // get the rec window size and seq num from receiver
    ctx->rec_win = ntohs(packet->th_win);
    if(ctx->rec_win == 0)
        ctx->rec_win = 1; // for flow control - if 0 try sending 1 byte
    ctx->rec_seq_num = ntohl(packet->th_seq);

    return true;
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

    // loop to run until connection is closed
    while (true)
    {
        // if connetion is closed, break out of loop
		if(ctx->connection_state == CLOSED){
			ctx->done = true;
			break;
		}
		
        // we need to wait for an event to know what to do
        unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);		
        
        // if we get data from the application, send it over network
		if(event == APP_DATA){
			if(!app_data_event(sd, ctx))
                return;
		}
		
        // if we get data from network, send it to application
		else if(event == NETWORK_DATA) {
			if(!network_data_event(sd, ctx))
                return;
		}
		
        // if we need to close the connection
		else if(event == APP_CLOSE_REQUESTED){
			if(!app_close_event(sd, ctx))
                return;
		}		
    }
}

// function for handling data received from application
bool app_data_event(mysocket_t sd, context_t *ctx){
	// figure out length
    ssize_t length = MIN(ctx->rec_win, MSS);
    length -= sizeof(STCPHeader);  // also need to account for header length

    char buffer[length];
    // now read and update the actual data length
    length = stcp_app_recv(sd, buffer, length);
    if(length == 0) {
        // could not send if here
        errno = ECONNREFUSED;
        // free unneeded memory
        free(ctx);
        return false;
    }

    // send packet
    if(!send_packet(sd, ctx, NETWORK_DATA, buffer, length))
        return false;
    
    // get ack
    if(!get_packet(sd, ctx, TH_ACK))
        return false;

    return true;
}

// when receiving network data
bool network_data_event(mysocket_t sd, context_t* ctx) {
    char buffer[MSS]; //payload
    
    // read data from network
    ssize_t bytes = stcp_network_recv(sd, buffer, MSS);
    if (bytes < (signed)sizeof(STCPHeader)) {
        free(ctx);
        errno = ECONNREFUSED;
        return false;
    }

    // get headers from the read data
    STCPHeader* bufferHeader = (STCPHeader*)buffer;
    ctx->rec_seq_num = ntohl(bufferHeader->th_seq);
    ctx->rec_win = ntohs(bufferHeader->th_win);

    // if it has fin flag then connection will close
    if (bufferHeader->th_flags == TH_FIN) {
        send_packet(sd, ctx, TH_ACK, NULL, 0);
        stcp_fin_received(sd);
        ctx->connection_state = CLOSED;
    }    
    // otherwise read the data from the packet and send it to application
    else {  
        stcp_app_send(sd, buffer + sizeof(STCPHeader), bytes - sizeof(STCPHeader));
        // finally send an ack
        send_packet(sd, ctx, TH_ACK, NULL, 0);
    }
    return true;
}

// when closing the app
bool app_close_event(mysocket_t sd, context_t* ctx){
	if(ctx->connection_state == CSTATE_ESTABLISHED) {
        if(!send_packet(sd, ctx, TH_FIN, NULL, 0)) {
            // unable to send :(
            free(ctx);
            errno = ECONNREFUSED;            
            return false;
        }
        ctx->connection_state = SENT_FIN;
		get_packet(sd, ctx, TH_ACK);
        ctx->connection_state = CLOSED;
    }
    return true;
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
