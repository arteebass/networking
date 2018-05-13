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
struct timeval tv;

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
typedef struct context_t
{
    bool_t done;    /* TRUE once connection is closed */
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
	unsigned int seq_num;
	unsigned int rec_seq_num;
	unsigned int rec_wind_size;
	
	struct recieverBuffer* rb;
	struct senderBuffer* sb;

    /* any other connection-wide global variables go here */
} ctx;

struct segment_t{
	unsigned int seqNumber;
	ssize_t length;
	bool acked;
	bool fin;
	char* data;
} ;

struct senderBuffer {
  char buffer[WINDOW_SIZE];
  char* endOfSegment;
  char* endOfAckdSegment;
  unsigned int nextSeq;
  segment_t* segments;
};

struct recieverBuffer {
  char buffer[WINDOW_SIZE];
  char* endOfSegment;
  unsigned int nextSeq;
  segment_t* segments;
};


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
// added funtions used
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, char* data, ssize_t length);
bool get_packet(mysocket_t sd, context_t *ctx, uint8_t flags);
bool get_ack(mysocket_t sd, context_t *ctx);
bool send_fin(mysocket_t sd, context_t* ctx);
void app_close_event(mysocket_t sd, context_t* ctx);
void network_data_event(mysocket_t sd, context_t* ctx);
bool app_data_event(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    printf("start\n");
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    printf("tryseqnum\n");
    generate_initial_seq_num(ctx);
    printf("genseqnum\n");

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if(is_active) {
        // send SYN packet
         printf("sendsyn\n");
        if(!send_packet(sd, ctx, TH_SYN, NULL, 0))
            return; // unable to send so exit out
        ctx->connection_state = SENT_SYN;

        printf("getsynack\n");
        // then we need to wait for the ack
        if(!get_packet(sd, ctx, (TH_SYN | TH_ACK)))
            return; // did not get syn ack        
        ctx->connection_state = RECV_SYN_ACK;

        printf("sendack\n");
        // finally ack the syn ack
        if(!send_packet(sd, ctx, TH_ACK, NULL, 0))
            return;
        ctx->connection_state = SENT_ACK;

    } else {
        // wait for SYN packet
        printf("getsyn\n");
        if(!get_packet(sd, ctx, TH_SYN))
            return;
        ctx->connection_state = RECV_SYN;

        printf("sendsynack\n");
        if(!send_packet(sd, ctx, (TH_SYN | TH_ACK), NULL, 0))
            return;
        ctx->connection_state = SENT_SYN_ACK;

        printf("getack\n");
        if(!get_packet(sd, ctx, TH_ACK))
            return;
        ctx->connection_state = RECV_ACK;
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    // got to control loop
    printf("ctrl loop\n");
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
    if(stcp_network_send(sd, packet, sizeof(STCPHeader)+length, NULL) > 0) {
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
    if(stcp_network_recv(sd, buffer, MSS) < sizeof(STCPHeader)) {
        // we did not recieve all the bytes that we should have gotten
        errno = ECONNREFUSED;        
        // free memory we dont need anymore
        free(ctx);
        //stcp_unblock_application(sd);
        return false;
    }

    // get packet info from buffer
    STCPHeader *packet = (STCPHeader*)buffer;

    // make sure it is a syn-ack packet
  //  if(packet->th_flags != flags) {
  //      // we did not recieve the right flags
  //      errno = ECONNREFUSED;
  //      // free memory we dont need anymore
  //      free(ctx);
  //      //stcp_unblock_application(sd);
  //      return false;
  //  }

    // get the rec window size and seq num from receiver
    ctx->rec_wind_size = ntohs(packet->th_win);
    if(ctx->rec_wind_size == 0)
        ctx->rec_wind_size = 1; // for flow control - if 0 try sending 1 byte

    ctx->rec_seq_num = ntohl(packet->th_seq);

    if (ctx->connection_state == SENT_FIN) {
      ctx->connection_state = CLOSED;
    }

    return true;
}

bool send_fin(mysocket_t sd, context_t* ctx){
	STCPHeader* fin_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
	fin_packet->th_seq = htonl(ctx->seq_num);
	fin_packet->th_ack = htonl(ctx->rec_seq_num + 1);
	fin_packet->th_flags = TH_FIN;
	fin_packet->th_win = htons(WINDOW_SIZE);
	fin_packet->th_off = htons(5);
	ctx->seq_num++;
	
	ssize_t sentBytes = stcp_network_send(sd, fin_packet, sizeof(STCPHeader), NULL);
	
	if(sentBytes > 0){
        printf("sent fin\n");    
		ctx->connection_state = SENT_FIN;
		get_packet(sd, ctx, TH_ACK);
		
		free(fin_packet);
		return true;
	} else {
		free(fin_packet);
		free(ctx);
		errno = ECONNREFUSED;
		return false;
	}
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
	int count = 0;

    printf("startloop\n");
    // loop to run until connetion is closed
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
            printf("appdata\n");
			gettimeofday(&tv, NULL);
			if(!app_data_event(sd, ctx))
                return;
		}
		
        // if we get data from network, send it to application
		if(event == NETWORK_DATA) {
            printf("networkdata\n");
			gettimeofday(&tv, NULL);
			network_data_event(sd, ctx);
		}
		
        // if we need to close the connection
		if(event == APP_CLOSE_REQUESTED){
            printf("close\n");
			gettimeofday(&tv, NULL);
			app_close_event(sd, ctx);
		}		
    }
}

bool app_data_event(mysocket_t sd, context_t *ctx){
	// figure out length
    ssize_t length = MIN(ctx->rec_wind_size, MSS);
    length -= sizeof(STCPHeader);  // also need to account for header length

    // then read that length from the application
    char buffer[length];
    if(stcp_app_recv(sd, buffer, length) == 0) {
        // could not send if here
        errno = ECONNREFUSED;
        // free unneeded memory
        free(ctx);
        return false;
    }

    printf("got app data\n");
    printf("\n");

    // send packet
    if(!send_packet(sd, ctx, NETWORK_DATA, buffer, length))
        return false;

    printf("sent app data\n");
    
    // get ack
    if(!get_packet(sd, ctx, TH_ACK))
        return false;

    printf("got ack\n");

    return true;
}

void network_data_event(mysocket_t sd, context_t* ctx) {
    bool isFIN = false;
    char buffer[MSS]; //payload
    
    ssize_t network_bytes = stcp_network_recv(sd, buffer, MSS);
    if (network_bytes < sizeof(STCPHeader)) {
        free(ctx);
        //stcp_unblock_application(sd);
        errno = ECONNREFUSED;  // TODO
        return;
    }

    STCPHeader* bufferHeader = (STCPHeader*)buffer;
    ctx->rec_seq_num = ntohl(bufferHeader->th_seq);
    ctx->rec_wind_size = ntohs(bufferHeader->th_win);
    isFIN = bufferHeader->th_flags == TH_FIN; //Boolean condition

    printf("read data\n");

    if (isFIN) {
        gettimeofday(&tv, NULL);
        send_packet(sd, ctx, TH_ACK, NULL, 0);
        stcp_fin_received(sd);
        ctx->connection_state = CLOSED;
        return;
    }

    printf("not is fin\n");
    
    if (network_bytes - sizeof(STCPHeader) > 0) {
        printf("remainder\n");    
        stcp_app_send(sd, buffer + sizeof(STCPHeader), network_bytes - sizeof(STCPHeader));
        send_packet(sd, ctx, TH_ACK, NULL, 0);
    } else {
        send_packet(sd, ctx, TH_ACK, NULL, 0);
    }
}

void app_close_event(mysocket_t sd, context_t* ctx){
	if(ctx->connection_state == CSTATE_ESTABLISHED)
		send_fin(sd, ctx);
	//prinf("connection_state: %d\n", ctx->connection_state);
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
