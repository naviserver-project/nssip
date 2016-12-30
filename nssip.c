/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Copyright (C) 2001-2004 Vlad Seryakov
 * All rights reserved.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * This module originally was based on same parts
 * from siproxd project (http://siproxd.sourceforge.net/)
 * regarding SIP parsrsing and processing.
 *
 */

/*
 * nssip.c -- SIP proxy
 *
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "ns.h"

#undef HAVE_CONFIG_H

#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_md5.h>
#include <osipparser2/sdp_message.h>


#define MOD_VERSION		"0.1"

#define SIP_USER        	"nssip" /* local sip user for tracking */
#define SIP_PORT		5060    /* default port to listen */
#define DEFAULT_MAXFWD		70      /* default Max-Forward count */

#define QUEUE_SIZE		16      /* max number of queue threads  */
#define BUFFER_SIZE		4096    /* input buffer for read from socket    */
#define URL_STRING_SIZE		128     /* max size of an URL/URI string        */
#define VIA_BRANCH_SIZE 	256     /* max string length for via branch param */
#define SEC_MIN_SIZE		16      /* minimum received length */
#define SEC_LINE_SIZE	        1024    /* maximum acceptable length of one line
                                           in the SIP telegram (security check)
                                           Careful: Proxy-Authorization lines may
                                           get quite long */

#define IFNULL(x)       	(x ? x : "NULL")

#define ROUTE_REWRITE_TO        1       /* update To: header */
#define ROUTE_REDIRECT          2       /* reply with redirect, no proxy */

/*
 * SIP client
 */
typedef struct _sip_client_t {
    Ns_RWLock lock;
    char ipaddr[16];
    Tcl_HashTable routes;
    struct _sip_client_t *link;
} sip_client_t;

/*
 * SIP route
 */
typedef struct _sip_route_t {
    short flags;
    char phone[16];
    char prefix[16];
    struct sockaddr_in host;
} sip_route_t;

typedef struct _sip_queue_t {
    int id;
    Ns_Cond cond;
    Ns_Mutex lock;
    unsigned long size;
    unsigned long maxsize;
    unsigned long requests;
    unsigned long time;
    struct _sip_proxy_t *proxy;
    struct _sip_ticket_t *head;
    struct _sip_ticket_t *tail;
    struct _sip_ticket_t *freelist;
} sip_queue_t;

/*
 * SIP proxy
 */
typedef struct _sip_proxy_t {
    int sock;
    int port;
    int debug;
    int rcvbuf;
    int threads;
    struct in_addr addr;
    char *magic;
    struct {
        Ns_RWLock lock;
        Tcl_HashTable list;
        sip_client_t *dflt;
    } client;
    sip_queue_t queue[QUEUE_SIZE];
} sip_proxy_t;

/*
 * SIP ticket
 */
typedef struct _sip_ticket_t {
    struct _sip_ticket_t *next;
    sip_proxy_t *proxy;
    osip_message_t *sipmsg;     /* SIP */
    struct sockaddr_in from;    /* received from */
    int protocol;               /* received by protocol */
    int direction;              /* direction as determined by proxy */
    int sock;
    int size;
    char buffer[BUFFER_SIZE];
} sip_ticket_t;

static int sipsock_resolve(char *host, struct in_addr *addr);
static int sipsock_send(sip_ticket_t * ticket, struct in_addr addr, int port, char *buffer, int size);

static int proxy_response(sip_ticket_t * ticket);
static int proxy_request(sip_ticket_t * ticket);

static int proxy_via_add(sip_ticket_t * ticket, struct in_addr *addr);
static int proxy_via_del(sip_ticket_t * ticket);
static int proxy_via_check(sip_ticket_t * ticket);
static int proxy_rr_add(sip_ticket_t * ticket);
static int proxy_rr_del(sip_ticket_t * ticket);
static int proxy_route_lookup(sip_ticket_t * ticket, struct in_addr *addr, int *port);
static int proxy_route_preprocess(sip_ticket_t * ticket);
static int proxy_route_postprocess(sip_ticket_t * ticket);

static osip_message_t *sip_message_reply(sip_ticket_t * ticket, int code);
static int sip_message_to_str(osip_message_t * sip, char **dest, int *len);
static int sip_message_send(sip_ticket_t * ticket, int code);

static int _sip_is_local(sip_ticket_t * ticket, struct in_addr addr, int port);
static int sip_is_local(sip_ticket_t * ticket, char *shost, char *sport);
static int sip_calculate_branch(sip_ticket_t * ticket, char *id);

static int security_check_raw(char *sip_buffer, int size);
static int security_check_sip(sip_ticket_t * ticket);

static char *int2str(int num);
static unsigned char *str2hex(unsigned char *from, int size, unsigned char *to);

static int sipInterpInit(Tcl_Interp * interp, void *arg);
static int sipCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static void sipListenThread(void *arg);
static void sipQueueThread(void *arg);
static void sipHandleRequest(sip_ticket_t * ticket);
static sip_client_t *SipClientFind(sip_proxy_t * proxy, char *host);
static sip_client_t *SipClientAdd(sip_proxy_t * proxy, char *host);
static void SipClientClear(sip_proxy_t * proxy, char *host);
static void SipClientLink(sip_proxy_t * proxy, char *host, char *host2);
static int SipRouteFind(sip_client_t * client, char *phone, sip_route_t * route);
static int SipRouteAdd(sip_client_t * client, char *phone, char *host);
static void SipRouteDel(sip_client_t * client, char *phone);

NS_EXPORT int Ns_ModuleVersion = 1;

static void Segv(int sig)
{
    Ns_Log(Error, "nssip: SIGSEGV received %d", getpid());
    while (1)
        sleep(1);
}

NS_EXPORT int Ns_ModuleInit(const char *server, const char *module)
{
    int i, n;
    sip_proxy_t *proxy;
    unsigned int l = sizeof(int);
    char *path, *address;

    // Init the oSIP parser
    parser_init();

    proxy = ns_calloc(1, sizeof(sip_proxy_t));
    proxy->magic = "z9hG4bK";

    Ns_RWLockInit(&proxy->client.lock);
    Tcl_InitHashTable(&proxy->client.list, TCL_ONE_WORD_KEYS);

    path = Ns_ConfigGetPath(server, module, NULL);

    if (!Ns_ConfigGetInt(path, "debug", &proxy->debug))
        proxy->debug = 0;
    if (!Ns_ConfigGetInt(path, "port", &proxy->port))
        proxy->port = SIP_PORT;
    if (!Ns_ConfigGetInt(path, "rcvbuf", &proxy->rcvbuf))
        proxy->rcvbuf = 0;
    if (!Ns_ConfigGetInt(path, "threads", &proxy->threads))
        proxy->threads = 1;
    if (proxy->threads > QUEUE_SIZE)
        proxy->threads = QUEUE_SIZE;

    // Address of the SIP proxy, if NULL hostname will used
    address = Ns_ConfigGetValue(path, "proxy_address");
    if (sipsock_resolve(address, &proxy->addr) == NS_ERROR) {
        Ns_Log(Error, "nssip: couldn't resolve proxy address: %s", address);
        return NS_ERROR;
    }
    // Create listen socket and register callback
    if (!(address = Ns_ConfigGetValue(path, "address")))
        address = "0.0.0.0";
    if ((proxy->sock = Ns_SockListenUdp(address, proxy->port, NS_FALSE)) == -1) {
        Ns_Log(Error, "nssip: %s:%d: couldn't create socket: %s", address, proxy->port, strerror(errno));
        return NS_ERROR;
    }
    if (proxy->rcvbuf) {
        setsockopt(proxy->sock, SOL_SOCKET, SO_RCVBUF, &proxy->rcvbuf, sizeof(proxy->rcvbuf));
        setsockopt(proxy->sock, SOL_SOCKET, SO_SNDBUF, &proxy->rcvbuf, sizeof(proxy->rcvbuf));
    }
    // Start queue threads
    for (n = 0; n < proxy->threads; n++) {
        proxy->queue[n].id = n;
        proxy->queue[n].proxy = proxy;
        // Preallocate SIP tickets
        for (i = 0; i <= proxy->threads * 10; i++) {
            sip_ticket_t *ticket = ns_calloc(1, sizeof(sip_ticket_t));
            ticket->next = proxy->queue[n].freelist;
            proxy->queue[n].freelist = ticket;
        }
        Ns_ThreadCreate(sipQueueThread, &proxy->queue[n], 0, 0);
    }
    // Start listen thread
    Ns_ThreadCreate(sipListenThread, proxy, 0, 0);
    signal(SIGSEGV, Segv);
    getsockopt(proxy->sock, SOL_SOCKET, SO_RCVBUF, &n, &l);
    Ns_Log(Notice, "nssip: listening on %s:%d, rcvbuf = %d (%d)", address, proxy->port, n, proxy->rcvbuf);
    Ns_TclRegisterTrace(server, sipInterpInit, proxy, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

static void sipListenThread(void *arg)
{
    sip_proxy_t *proxy = (sip_proxy_t *) arg;
    unsigned int len = sizeof(struct sockaddr_in);
    sip_ticket_t *ticket, buf;
    int id = 0;

    Ns_ThreadSetName("nssip:thread");

    while (1) {
        if ((buf.size = recvfrom(proxy->sock, buf.buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *) &buf.from, &len)) <= 0) {
            Ns_Log(Error, "nssip: recvfrom error: %s", strerror(errno));
            continue;
        }
        buf.proxy = proxy;
        buf.sock = proxy->sock;
        buf.buffer[buf.size] = 0;
        if (proxy->debug > 0) {
            Ns_Log(Debug, "nssip: received %d bytes from %s", buf.size, ns_inet_ntoa(buf.from.sin_addr));
            if (proxy->debug > 7)
                Ns_Log(Debug, buf.buffer);
        }
        /*
         *  Link new job into the queue
         */
        Ns_MutexLock(&proxy->queue[id].lock);
        if ((ticket = proxy->queue[id].freelist))
            proxy->queue[id].freelist = ticket->next;
        if (!ticket)
            ticket = ns_calloc(1, sizeof(sip_ticket_t));
        memcpy(ticket, &buf, sizeof(buf));
        if (proxy->queue[id].tail)
            proxy->queue[id].tail->next = ticket;
        proxy->queue[id].tail = ticket;
        if (!proxy->queue[id].head)
            proxy->queue[id].head = ticket;
        proxy->queue[id].size++;
        proxy->queue[id].requests++;
        Ns_CondBroadcast(&proxy->queue[id].cond);
        Ns_MutexUnlock(&proxy->queue[id].lock);
        if (++id >= proxy->threads)
            id = 0;
    }
}

static void sipQueueThread(void *arg)
{
    int sock;
    char buf[32];
    sip_queue_t *queue;
    sip_ticket_t *ticket;
    unsigned long t0;
    struct timeval t1, t2;

    queue = (sip_queue_t *) arg;
    sprintf(buf, "nssip:queue:%d", queue->id);
    Ns_Log(Notice, "Starting thread: %s", buf);
    Ns_ThreadSetName(buf);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (queue->proxy->rcvbuf) {
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &queue->proxy->rcvbuf, sizeof(queue->proxy->rcvbuf));
    }
    Ns_MutexInit(&queue->lock);
    Ns_MutexSetName(&queue->lock, buf);
    Ns_MutexLock(&queue->lock);
    while (1) {
        while (!queue->head) {
            Ns_CondWait(&queue->cond, &queue->lock);
        }
        gettimeofday(&t1, 0);
        /*
         *  Unlink first job from the queue
         */
        ticket = queue->head;
        queue->head = ticket->next;
        if (queue->tail == ticket)
            queue->tail = 0;
        if (queue->size > queue->maxsize)
            queue->maxsize = queue->size;
        queue->size--;
        Ns_MutexUnlock(&queue->lock);
        ticket->sock = sock;
        sipHandleRequest(ticket);
        ticket->next = queue->freelist;
        queue->freelist = ticket;
        Ns_MutexLock(&queue->lock);
        Ns_CondBroadcast(&queue->cond);
        gettimeofday(&t2, 0);
        t0 = ((t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec)) / 1000;
        if (t0 > queue->time)
            queue->time = t0;
    }
}

static int sipInterpInit(Tcl_Interp * interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_sip", sipCmd, arg, NULL);
    return NS_OK;
}

static int sipCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    enum commands {
        cmdRouteAdd,
        cmdRouteDel,
        cmdRouteList,
        cmdRouteFind,
        cmdClientClear,
        cmdClientLink,
        cmdClientList,
        cmdQueueStat
    };

    static const char *sCmd[] = {
        "routeadd",
        "routedel",
        "routelist",
        "routefind",
        "clientclear",
        "clientlink",
        "clientlist",
        "queuestat",
        0
    };
    int i, cmd;
    char tmp[255];
    unsigned long n, r;
    struct in_addr addr;
    sip_route_t *route;
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;
    sip_client_t *client = 0;
    sip_proxy_t *proxy = (sip_proxy_t *) arg;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "command ...");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    // Command preprocessing, find the client, etc...
    switch (cmd) {
    case cmdRouteFind:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip phone");
            return TCL_ERROR;
        }
        client = SipClientFind(proxy, Tcl_GetString(objv[2]));
        if (!client)
            return TCL_OK;
        break;

    case cmdRouteDel:
    case cmdRouteList:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip ...");
            return TCL_ERROR;
        }
        client = SipClientFind(proxy, Tcl_GetString(objv[2]));
        if (!client)
            return TCL_OK;
        break;

    case cmdRouteAdd:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip phone proxy[:port][#prefix][?t] phone proxy ...");
            return TCL_ERROR;
        }
        client = SipClientAdd(proxy, Tcl_GetString(objv[2]));
        if (!client)
            return TCL_OK;
        break;

    case cmdClientClear:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip ...");
            return TCL_ERROR;
        }
        SipClientClear(proxy, Tcl_GetString(objv[2]));
        break;

    case cmdClientLink:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "clientip clientip2");
            return TCL_ERROR;
        }
        SipClientLink(proxy, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
        break;

    case cmdQueueStat:
        for (n = 0, r = 0, i = 0; i < proxy->threads; i++) {
            n += proxy->queue[i].size;
            r += proxy->queue[i].requests;
            sprintf(tmp, "size%d %lu maxsize%d %lu time%d %lu requests%d %lu ", i, proxy->queue[i].size, i,
                    proxy->queue[i].maxsize, i, proxy->queue[i].time, i, proxy->queue[i].requests);
            Tcl_AppendResult(interp, tmp, 0);
        }
        sprintf(tmp, "total %lu requests %lu", n, r);
        Tcl_AppendResult(interp, tmp, 0);
        return TCL_OK;
    }

    // Actual command processing
    switch (cmd) {
    case cmdRouteAdd:
        for (i = 3; i < objc - 1; i += 2) {
            SipRouteAdd(client, Tcl_GetString(objv[i]), Tcl_GetString(objv[i + 1]));
        }
        break;

    case cmdRouteDel:
        SipRouteDel(client, objc > 3 ? Tcl_GetString(objv[3]) : 0);
        break;

    case cmdRouteFind:{
            char tmp[32];
            sip_route_t r;
            if (SipRouteFind(client, Tcl_GetString(objv[3]), &r) == NS_ERROR)
                break;
            Tcl_AppendResult(interp, "client ", client->ipaddr, 0);
            sprintf(tmp, "%d", r.flags);
            Tcl_AppendResult(interp, " flags ", tmp, 0);
            Tcl_AppendResult(interp, " prefix {", r.prefix, "} host ", ns_inet_ntoa(r.host.sin_addr), 0);
            sprintf(tmp, "%d", r.host.sin_port);
            Tcl_AppendResult(interp, " port ", tmp, 0);
            break;
        }

    case cmdRouteList:
        Ns_RWLockWrLock(&client->lock);
        entry = Tcl_FirstHashEntry(&client->routes, &search);
        while (entry) {
            Tcl_AppendElement(interp, Tcl_GetHashKey(&client->routes, entry));
            route = Tcl_GetHashValue(entry);
            sprintf(tmp, "%s:%i%s%s%s%s%s", ns_inet_ntoa(route->host.sin_addr),
                    route->host.sin_port, route->prefix[0] ? "#" : "", route->prefix,
                    route->flags ? "?" : "",
                    route->flags & ROUTE_REWRITE_TO ? "t" : "", route->flags & ROUTE_REDIRECT ? "r" : "");
            Tcl_AppendElement(interp, tmp);
            entry = Tcl_NextHashEntry(&search);
        }
        Ns_RWLockUnlock(&client->lock);
        break;

    case cmdClientList:
        Ns_RWLockWrLock(&proxy->client.lock);
        entry = Tcl_FirstHashEntry(&proxy->client.list, &search);
        while (entry) {
            addr.s_addr = (unsigned long) Tcl_GetHashKey(&proxy->client.list, entry);
            Tcl_AppendElement(interp, ns_inet_ntoa(addr));
            entry = Tcl_NextHashEntry(&search);
        }
        Ns_RWLockUnlock(&proxy->client.lock);
        break;
    }
    return TCL_OK;
}

static void sipHandleRequest(sip_ticket_t * ticket)
{
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;
    osip_header_t *max_forwards;
    int forwards_count = DEFAULT_MAXFWD;

    /* integrity checks - raw buffer */
    if (security_check_raw(ticket->buffer, ticket->size) != NS_OK)
        return;

    if (osip_message_init(&ticket->sipmsg))
        return;
    ticket->sipmsg->message = NULL;

    /*
     * RFC 3261, Section 16.3 step 1
     * Proxy Behavior - Request Validation - Reasonable Syntax
     * (parse the received message)
     */

    if (osip_message_parse(ticket->sipmsg, ticket->buffer, ticket->size) != 0) {
        Ns_Log(Debug, "Bad SIP message from");
        osip_message_free(ticket->sipmsg);
        return;
    }

    /* integrity checks - parsed message */
    if (security_check_sip(ticket) != NS_OK) {
        osip_message_free(ticket->sipmsg);
        return;
    }
    /*
     * RFC 3261, Section 16.3 step 2
     * Proxy Behavior - Request Validation - URI scheme
     * (check request URI and refuse with 416 if not understood)
     */
    /* NOT IMPLEMENTED */

    /*
     * RFC 3261, Section 16.3 step 3
     * Proxy Behavior - Request Validation - Max-Forwards check
     * (check Max-Forwards header and refuse with 483 if too many hops)
     */

    osip_message_get_max_forwards(ticket->sipmsg, 0, &max_forwards);
    if (max_forwards && max_forwards->hvalue)
        forwards_count = atoi(max_forwards->hvalue);
    if (forwards_count <= 0) {
        Ns_Log(Debug, "Forward count reached 0 -> 483 response");
        sip_message_send(ticket, 483);
        osip_message_free(ticket->sipmsg);
        return;
    }

    /*
     * RFC 3261, Section 16.3 step 4
     * Proxy Behavior - Request Validation - Loop Detection check
     * (check for loop and return 482 if a loop is detected)
     */

    if (proxy_via_check(ticket) == NS_ERROR) {
        /* make sure we don't end up in endless loop when detecting
         * an loop in an "loop detected" message - brrr */
        if (MSG_IS_RESPONSE(ticket->sipmsg) && MSG_TEST_CODE(ticket->sipmsg, 482)) {
            Ns_Log(Debug, "loop in loop-response detected, ignoring");
        } else {
            Ns_Log(Debug, "via loop detected, ignoring request");
            sip_message_send(ticket, 482);
        }
        osip_message_free(ticket->sipmsg);
        return;
    }

    /*
     * RFC 3261, Section 16.3 step 5
     * Proxy Behavior - Request Validation - Proxy-Require check
     * (check Proxy-Require header and return 420 if unsupported option)
     */
    /* NOT IMPLEMENTED */

    /*
     * RFC 3261, Section 16.5
     * Proxy Behavior - Determining Request Targets
     *
     */
    if (proxy->debug > 0)
        Ns_Log(Debug, "received %s %d",
               MSG_IS_REQUEST(ticket->sipmsg) ? IFNULL(ticket->sipmsg->sip_method) : IFNULL(ticket->sipmsg->reason_phrase),
               ticket->sipmsg->status_code);

    if (MSG_IS_REQUEST(ticket->sipmsg)) {

        proxy_request(ticket);

    } else
     if (MSG_IS_RESPONSE(ticket->sipmsg)) {

        proxy_response(ticket);

    } else
        Ns_Log(Error, "received unsupported SIP %s %s", (MSG_IS_REQUEST(ticket->sipmsg)) ? "request" : "response",
               ticket->sipmsg->sip_method);

    osip_message_free(ticket->sipmsg);
}

static sip_client_t *SipClientAdd(sip_proxy_t * proxy, char *host)
{
    int new;
    struct in_addr addr;
    sip_client_t *client;
    Tcl_HashEntry *entry;

    if (sipsock_resolve(host, &addr) == NS_ERROR) {
        Ns_Log(Error, "SipClientAdd: unable to resolve %s", host);
        return 0;
    }
    Ns_RWLockWrLock(&proxy->client.lock);
    entry = Tcl_CreateHashEntry(&proxy->client.list, (char *) addr.s_addr, &new);
    Ns_RWLockUnlock(&proxy->client.lock);
    if (new) {
        client = ns_calloc(1, sizeof(sip_client_t));
        strcpy(client->ipaddr, ns_inet_ntoa(addr));
        Ns_RWLockInit(&client->lock);
        Tcl_InitHashTable(&client->routes, TCL_STRING_KEYS);
        Tcl_SetHashValue(entry, (ClientData) client);
        if (!strcmp(host, "0.0.0.0"))
            proxy->client.dflt = client;
    }
    return Tcl_GetHashValue(entry);
}

static sip_client_t *SipClientFind(sip_proxy_t * proxy, char *host)
{
    struct in_addr addr;
    Tcl_HashEntry *entry;

    if (sipsock_resolve(host, &addr) == NS_ERROR) {
        Ns_Log(Error, "SipClientFind: unable to resolve %s", host);
        return 0;
    }
    Ns_RWLockRdLock(&proxy->client.lock);
    entry = Tcl_FindHashEntry(&proxy->client.list, (char *) addr.s_addr);
    Ns_RWLockUnlock(&proxy->client.lock);
    if (entry)
        return Tcl_GetHashValue(entry);
    return proxy->client.dflt;
}

static void SipClientClear(sip_proxy_t * proxy, char *host)
{
    struct in_addr addr;
    Tcl_HashEntry *entry;
    sip_client_t *client;

    if (sipsock_resolve(host, &addr) == NS_ERROR) {
        Ns_Log(Error, "SipClientClear: unable to resolve %s", host);
        return;
    }
    Ns_RWLockWrLock(&proxy->client.lock);
    entry = Tcl_FindHashEntry(&proxy->client.list, (char *) addr.s_addr);
    Ns_RWLockUnlock(&proxy->client.lock);
    if (!entry)
        return;
    client = (sip_client_t *) Tcl_GetHashValue(entry);
    SipRouteDel(client, 0);
}

static void SipClientLink(sip_proxy_t * proxy, char *host, char *host2)
{
    sip_client_t *client, *client2;

    if ((client = SipClientAdd(proxy, host)) && (client2 = SipClientAdd(proxy, host2))) {
        client2->link = client;
    }
}

static int SipRouteAdd(sip_client_t * client, char *phone, char *host)
{
    char *port, *prefix, *flags;
    int new;
    struct in_addr addr;
    sip_route_t *route;
    Tcl_HashEntry *entry;

    if ((flags = strchr(host, '?')))
        *flags++ = 0;
    if ((prefix = strchr(host, '#')))
        *prefix++ = 0;
    if ((port = strchr(host, ':')))
        *port++ = 0;
    if (sipsock_resolve(host, &addr) == NS_ERROR) {
        Ns_Log(Error, "SipRouteAdd: unable to resolve %s", host);
        return NS_ERROR;
    }
    Ns_RWLockWrLock(&client->lock);
    entry = Tcl_CreateHashEntry(&client->routes, phone, &new);
    if (new) {
        route = ns_calloc(1, sizeof(sip_proxy_t));
        Tcl_SetHashValue(entry, (ClientData) route);
    }
    route = Tcl_GetHashValue(entry);
    route->flags = 0;
    route->prefix[0] = 0;
    route->host.sin_addr = addr;
    route->host.sin_port = port ? atoi(port) : SIP_PORT;
    if (prefix)
        strncpy(route->prefix, prefix, sizeof(route->prefix));
    strncpy(route->phone, Tcl_GetHashKey(&client->routes, entry), sizeof(route->phone));
    /*
     * Parse rewrite flags
     */
    if (flags) {
        if (strchr(flags, 't'))
            route->flags |= ROUTE_REWRITE_TO;
        if (strchr(flags, 'r'))
            route->flags |= ROUTE_REDIRECT;
    }
    Ns_RWLockUnlock(&client->lock);
    return NS_OK;
}

static int SipRouteFind(sip_client_t * client, char *str, sip_route_t * route)
{
    Tcl_HashEntry *entry;
    char phone[256], *ptr;

    Ns_RWLockRdLock(&client->lock);
    snprintf(phone, sizeof(phone), "%s", str);
    for (ptr = &phone[strlen(phone) - 1]; ptr >= phone; *(ptr--) = 0) {
        entry = Tcl_FindHashEntry(&client->routes, phone);
        if (entry) {
            memcpy(route, Tcl_GetHashValue(entry), sizeof(sip_route_t));
            Ns_RWLockUnlock(&client->lock);
            return NS_OK;
        }
    }
    Ns_RWLockUnlock(&client->lock);
    return NS_ERROR;
}

static void SipRouteDel(sip_client_t * client, char *phone)
{
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    Ns_RWLockWrLock(&client->lock);
    // Delete all routes from the client
    entry = Tcl_FirstHashEntry(&client->routes, &search);
    while (entry) {
        if (!phone || !strcmp(phone, Tcl_GetHashKey(&client->routes, entry))) {
            ns_free(Tcl_GetHashValue(entry));
            Tcl_DeleteHashEntry(entry);
        }
        entry = Tcl_NextHashEntry(&search);
    }
    // When removing everything, clear link as well
    if (!phone)
        client->link = 0;
    Ns_RWLockUnlock(&client->lock);
}

/*
 * PROXY_REQUEST
 *
 * RETURNS
 *	NS_OK on success
 *	STS_FAILURE on error
 *
 * RFC3261
 *    Section 16.3: Proxy Behavior - Request Validation
 *    1. Reasonable Syntax
 *    2. URI scheme
 *    3. Max-Forwards
 *    4. (Optional) Loop Detection
 *    5. Proxy-Require
 *    6. Proxy-Authorization
 *
 *    Section 16.6: Proxy Behavior - Request Forwarding
 *    1.  Make a copy of the received request
 *    2.  Update the Request-URI
 *    3.  Update the Max-Forwards header field
 *    4.  Optionally add a Record-route header field value
 *    5.  Optionally add additional header fields
 *    6.  Postprocess routing information
 *    7.  Determine the next-hop address, port, and transport
 *    8.  Add a Via header field value
 *    9.  Add a Content-Length header field if necessary
 *    10. Forward the new request
 *    11. Set timer C
 */
static int proxy_request(sip_ticket_t * ticket)
{
    int port;
    int buflen;
    char mfwd[8];
    char *buffer;
    osip_uri_t *uri;
    sip_proxy_t *proxy;
    osip_message_t *request;
    struct sockaddr_in *from;
    struct in_addr reply_addr;
    osip_header_t *max_forwards;
    int forwards_count = DEFAULT_MAXFWD;

    proxy = ticket->proxy;
    request = ticket->sipmsg;
    from = &ticket->from;

    /*
     * RFC 3261, Section 16.4
     * Proxy Behavior - Route Information Preprocessing
     * (process Route header)
     */

    proxy_route_preprocess(ticket);

    /*
     * RFC 3261, Section 16.6 step 1
     * Proxy Behavior - Request Forwarding - Make a copy
     */
    /* NOT IMPLEMENTED */

    /* get destination address */
    uri = osip_message_get_uri(request);

    if (proxy->debug > 1)
        Ns_Log(Debug, "Request from %s@%s (%s@%s) for %s@%s", IFNULL(request->from->url->username),
               IFNULL(request->from->url->host), IFNULL(request->to->url->username), IFNULL(request->to->url->host),
               IFNULL(uri->username), IFNULL(uri->host));

    /*
     * RFC 3261, Section 16.6 step 2
     * Proxy Behavior - Request Forwarding - Analyze Request-URI
     */
    /* NOT IMPLEMENTED */

    /*
     * RFC 3261, Section 16.6 step 3
     * Proxy Behavior - Request Forwarding - Max-Forwards
     * (if Max-Forwards header exists, decrement by one, if it does not
     * exist, add a new one with value SHOULD be 70)
     */

    osip_message_get_max_forwards(request, 0, &max_forwards);
    if (max_forwards == NULL) {
        sprintf(mfwd, "%i", forwards_count);
        osip_message_set_max_forwards(request, mfwd);
    } else {
        if (max_forwards->hvalue) {
            forwards_count = atoi(max_forwards->hvalue) - 1;
            osip_free(max_forwards->hvalue);
        }
        max_forwards->hvalue = int2str(forwards_count);
    }

    /*
     * RFC 3261, Section 16.6 step 4
     * Proxy Behavior - Request Forwarding - Add a Record-route header
     */

    proxy_rr_add(ticket);

    /*
     * RFC 3261, Section 16.6 step 5
     * Proxy Behavior - Request Forwarding - Add Additional Header Fields
     */
    /* NOT IMPLEMENTED (optional) */


    /*
     * RFC 3261, Section 16.6 step 6
     * Proxy Behavior - Request Forwarding - Postprocess routing information
     */

    proxy_route_postprocess(ticket);

    /*
     * RFC 3261, Section 16.6 step 7
     * Proxy Behavior - Determine Next-Hop Address
     *
     */

    if (proxy_route_lookup(ticket, &reply_addr, &port) == NS_OK) {

        /*
         * Outbound proxy resolved
         */

        if (proxy->debug > 2)
            Ns_Log(Debug, "proxy_request: sending to outbound proxy %s:%i", ns_inet_ntoa(reply_addr), port);

    } else {

        /* 
         * Get the destination from the SIP URI
         */

        if (sipsock_resolve(uri->host, &reply_addr) == NS_ERROR) {
            Ns_Log(Error, "proxy_request: cannot resolve URI [%s]", uri->host);
            return NS_ERROR;
        }
        port = uri->port ? atoi(uri->port) : SIP_PORT;

        if (proxy->debug > 2)
            Ns_Log(Debug, "proxy_request: sending to SIP URI to %s:%i", uri->host, port);
    }

    /*
     * Check if URI point to us to avoid loops
     */

    if (_sip_is_local(ticket, reply_addr, port) == NS_TRUE) {
        Ns_Log(Error, "proxy_request: request URI point to myself [%s:%i]", ns_inet_ntoa(reply_addr), port);
        sip_message_send(ticket, 482);
        return NS_ERROR;
    }

    /*
     * RFC 3261, Section 16.6 step 8
     * Proxy Behavior - Add a Via header field value
     */

    proxy_via_add(ticket, &proxy->addr);

    /*
     * RFC 3261, Section 16.6 step 9
     * Proxy Behavior - Add a Content-Length header field if necessary
     */
    /* NOT IMPLEMENTED */

    /*
     * RFC 3261, Section 16.6 step 10
     * Proxy Behavior - Forward the new request
     */

    if (sip_message_to_str(request, &buffer, &buflen)) {
        Ns_Log(Error, "proxy_request: sip_message_to_str failed");
        return NS_ERROR;
    }

    sipsock_send(ticket, reply_addr, port, buffer, buflen);
    osip_free(buffer);

    /*
     * RFC 3261, Section 16.6 step 11
     * Proxy Behavior - Set timer C
     */
    /* NOT IMPLEMENTED */

    return NS_OK;
}


/*
 * PROXY_RESPONSE
 *
 * RETURNS
 *	NS_OK on success
 *	NS_ERROR on error
 * RFC3261
 *    Section 16.7: Proxy Behavior - Response Processing
 *    1.  Find the appropriate response context
 *    2.  Update timer C for provisional responses
 *    3.  Remove the topmost Via
 *    4.  Add the response to the response context
 *    5.  Check to see if this response should be forwarded immediately
 *    6.  When necessary, choose the best final response from the
 *        response context
 *    7.  Aggregate authorization header field values if necessary
 *    8.  Optionally rewrite Record-Route header field values
 *    9.  Forward the response
 *    10. Generate any necessary CANCEL requests 
 *
 */
static int proxy_response(sip_ticket_t * ticket)
{
    int port;
    char *buffer;
    int buflen;
    osip_via_t *via;
    osip_route_t *route;
    struct in_addr reply_addr;
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;
    osip_message_t *response = ticket->sipmsg;

    if (proxy->debug > 1)
        Ns_Log(Debug, "Response '%d %s' from %s@%s to %s%s", response->status_code, IFNULL(response->reason_phrase),
               IFNULL(response->from->url->username), IFNULL(response->from->url->host), IFNULL(response->to->url->username),
               IFNULL(response->to->url->host));

    /*
     * RFC 3261, Section 16.7 step 3
     * Proxy Behavior - Response Processing - Remove my Via header field value
     */

    if (proxy_via_del(ticket) == NS_ERROR)
        return NS_ERROR;

    /*
     * RFC 3261, Section 16.7 step 8  
     * Proxy Behavior - Response Forwarding
     * Optionally rewrite Record-Route header field values
     */

    proxy_rr_del(ticket);

    /*
     * Determine Next-Hop Address
     */

    if (response->routes && !osip_list_eol(response->routes, 0)) {

        /*
         * Check for existing route header, the topmost will be the next hop.
         */

        route = (osip_route_t *) osip_list_get(response->routes, 0);
        if (!route || !route->url || !route->url->host) {
            Ns_Log(Error, "proxy_response: got broken Route header - discarding packet");
            return NS_ERROR;
        }
        if (sipsock_resolve(route->url->host, &reply_addr) == NS_ERROR) {
            Ns_Log(Error, "proxy_response: cannot resolve Route URI [%s]", route->url->host);
            return NS_ERROR;
        }
        port = route->url->port ? atoi(route->url->port) : SIP_PORT;
        osip_list_remove(response->routes, 0);
        osip_route_free(route);
        if (proxy->debug > 2)
            Ns_Log(Debug, "proxy_response: send to Route header %s:%i", ns_inet_ntoa(reply_addr), port);

    } else {

        /*
         * get target address and port from VIA header
         */

        via = (osip_via_t *) osip_list_get(response->vias, 0);
        if (sipsock_resolve(via->host, &reply_addr) == NS_ERROR) {
            Ns_Log(Error, "proxy_response: cannot resolve VIA [%s]", via->host);
            return NS_ERROR;
        }
        port = via->port ? atoi(via->port) : SIP_PORT;
        if (proxy->debug > 2)
            Ns_Log(Debug, "proxy_response: send to VIA %s:%i", via->host, port);
    }

    if (sip_message_to_str(response, &buffer, &buflen)) {
        Ns_Log(Error, "proxy_response: sip_message_to_str failed");
        return NS_ERROR;
    }

    sipsock_send(ticket, reply_addr, port, buffer, buflen);
    osip_free(buffer);

    return NS_OK;
}


/*
 * check for a via loop.
 *
 * 1) for requests, I must search the whole VIA list
 *   (topmost via is the previos station in the path)
 *
 * 2) for responses I must skip the topmost via, as this is mine
 *   (and will be removed later on)
 *
 * RETURNS
 *	NS_ERROR if loop detected
 *	NS_OK if no loop
 */
static int proxy_via_check(sip_ticket_t * ticket)
{
    osip_message_t *my_msg = ticket->sipmsg;
    osip_via_t *via;
    int pos = 1;
    int found_own_via = 0;

    /* for detecting a loop, don't check the first entry as this is my own VIA! */
    while (!osip_list_eol(my_msg->vias, pos)) {
        via = (osip_via_t *) osip_list_get(my_msg->vias, pos);
        if (sip_is_local(ticket, via->host, via->port) == NS_TRUE)
            found_own_via += 1;
        pos++;
    }

    /*
     * what happens if a message is coming back to me legally?
     *  UA1 -->--\       /-->--\
     *            proxy       Registrar
     *  UA2 --<--/       \--<--/
     *
     * This may also lead to a VIA loop - so I probably must take the branch
     * parameter into count (or a unique part of it) OR just allow at least 2
     * vias of my own.
     */
    return (found_own_via > 2) ? NS_ERROR : NS_OK;
}

/*
 *
 * RETURNS
 *	NS_OK on success
 *	NS_ERROR on error
 */
static int proxy_via_add(sip_ticket_t * ticket, struct in_addr *addr)
{
    osip_via_t *via;
    char tmp[URL_STRING_SIZE];
    char branch[VIA_BRANCH_SIZE];

    if (osip_via_init(&via))
        return NS_ERROR;

    sip_calculate_branch(ticket, branch);

    snprintf(tmp, sizeof(tmp), "SIP/2.0/UDP %s:%i;branch=%s", ns_inet_ntoa(*addr), ticket->proxy->port, branch);
    if (ticket->proxy->debug > 3)
        Ns_Log(Debug, "adding Via: %s", tmp);

    if (osip_via_parse(via, tmp)) {
        osip_via_free(via);
        return NS_ERROR;
    }
    osip_list_add(ticket->sipmsg->vias, via, 0);

    return NS_OK;
}


/*
 *
 * RETURNS
 *	NS_OK on success
 *	NS_ERROR on error
 */
static int proxy_via_del(sip_ticket_t * ticket)
{
    osip_via_t *via = osip_list_get(ticket->sipmsg->vias, 0);

    if (sip_is_local(ticket, via->host, via->port) == NS_FALSE) {
        Ns_Log(Error, "unable to delete my VIA: host=%s:%s", via->host, via->port);
        return NS_ERROR;
    }

    osip_list_remove(ticket->sipmsg->vias, 0);
    osip_via_free(via);
    return NS_OK;
}

/*
 *
 * performs the lookup for an apropriate outbound proxy
 *
 * RETURNS
 *	NS_OK on successful lookup
 *	NS_ERROR if no outbound proxy to be used
 */
static int proxy_route_lookup(sip_ticket_t * ticket, struct in_addr *addr, int *port)
{
    osip_message_t *msg = ticket->sipmsg;
    osip_uri_t *uri = osip_message_get_uri(msg);
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;
    sip_client_t *client;
    sip_route_t route;

    // phone should present in the request URI
    if (!uri->username)
        return NS_ERROR;

    client = SipClientFind(ticket->proxy, ns_inet_ntoa(ticket->from.sin_addr));
    if (!client)
        return NS_ERROR;

    // Use linked client routes
    if (client->link)
        client = client->link;
    if (SipRouteFind(client, uri->username, &route) == NS_ERROR)
        return NS_ERROR;

    if (proxy->debug > 3)
        Ns_Log(Debug, "proxy_route_lookup: found %s:%d to %s%s%s", ns_inet_ntoa(route.host.sin_addr), route.host.sin_port,
               route.prefix, route.prefix[0] ? "#" : "", route.phone);

    /*
     * Route found, return new proxy address
     */

    *port = route.host.sin_port;
    memcpy(addr, &route.host.sin_addr, sizeof(struct in_addr));

    if (!MSG_IS_REQUEST(msg))
        return NS_OK;

    if (route.prefix[0]) {
        char *username = osip_malloc(strlen(uri->username) + strlen(route.prefix) + 2);
        sprintf(username, "%s#%s", route.prefix, uri->username);
        osip_uri_set_username(uri, username);
    }

    /*
     * Update request uri with new host:port and prefix
     */

    osip_uri_set_host(uri, osip_strdup(ns_inet_ntoa(route.host.sin_addr)));
    osip_uri_set_port(uri, int2str(route.host.sin_port));

    /*
     * Reply with redirect, no proxy required
     */

    if (route.flags & ROUTE_REDIRECT) {
        osip_via_t *via;
        osip_contact_t *contact;

        osip_free(msg->sip_method);
        msg->sip_method = 0;
        osip_message_set_status_code(msg, 302);
        osip_message_set_reason_phrase(msg, osip_strdup(osip_message_get_reason(302)));

        /*
         * Send redirect to the first Via:
         */
        osip_message_get_via(msg, 0, &via);
        if (via == NULL) {
            Ns_Log(Error, "proxy_route_lookup: Cannot send redirect - continue with proxy");
            return NS_OK;
        }
        if (sipsock_resolve(via->host, addr) == NS_ERROR) {
            Ns_Log(Error, "proxy_route_lookup: cannot resolve via [%s]", via->host);
            return NS_ERROR;
        }
        *port = via->port ? atoi(via->port) : SIP_PORT;

        /*
         *  Add/rewrite contact header with new location
         */
        osip_message_get_contact(msg, 0, &contact);
        osip_list_remove(msg->contacts, 0);
        if (contact)
            osip_contact_free(contact);
        osip_contact_init(&contact);
        osip_uri_clone(uri, &contact->url);
        osip_list_add(msg->contacts, contact, -1);
        return NS_OK;
    }

    /*
     * Update To: header with the same value as URI
     */

    if (route.flags & ROUTE_REWRITE_TO) {
        osip_uri_set_host(msg->to->url, osip_strdup(uri->host));
        osip_uri_set_port(msg->to->url, osip_strdup(uri->port));
        osip_uri_set_username(msg->to->url, osip_strdup(uri->username));
    }
    return NS_OK;
}

/*
 *
 * Route Information Preprocessing
 *
 * 16.4 Route Information Preprocessing:
 *
 * The proxy MUST inspect the Request-URI of the request.  If the
 * Request-URI of the request contains a value this proxy previously
 * placed into a Record-Route header field (see Section 16.6 item 4),
 * the proxy MUST replace the Request-URI in the request with the last
 * value from the Route header field, and remove that value from the
 * Route header field.  The proxy MUST then proceed as if it received
 * this modified request.
 *
 * RETURNS
 *	NS_OK on success
 */
static int proxy_route_preprocess(sip_ticket_t * ticket)
{
    int last;
    osip_uri_t *url;
    osip_route_t *route;
    osip_uri_param_t *param = NULL;
    osip_message_t *msg = ticket->sipmsg;
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;

    if (!msg->routes || osip_list_size(msg->routes) <= 0)
        return NS_OK;

    url = osip_message_get_uri(msg);

    if (!strcmp(IFNULL(url->username), SIP_USER) && sip_is_local(ticket, url->host, url->port)) {
        /* Request URI points to myself */
        if (proxy->debug > 4)
            Ns_Log(Debug, "request URI [%s@%s:%s] points to myself", url->username, url->host, IFNULL(url->port));

        /* get last route in list */
        last = osip_list_size(msg->routes) - 1;
        route = (osip_route_t *) osip_list_get(msg->routes, last);
        if (proxy->debug > 4)
            Ns_Log(Debug, "moving last Route [%s@%s:%s] to URI", IFNULL(route->url->username), IFNULL(route->url->host),
                   IFNULL(route->url->port));

        /*
         * issue warning if the Route I'm going to fetch is NOT
         * a strict router (lr parameter not present) - something is fishy
         */

        if (!osip_uri_uparam_get_byname(route->url, "lr", &param)) {
            Ns_Log(Error, "Fixup Strict Router: Route entry [%s@%s:%s] is not a strict Router!",
                   IFNULL(route->url->username), IFNULL(route->url->host), IFNULL(route->url->port));
        }
        /* rewrite request URI */
        osip_uri_free(url);
        osip_uri_clone(route->url, &(msg->req_uri));

        /* remove from list */
        osip_list_remove(msg->routes, last);
        osip_route_free(route);
    }

    /*
     * 16.4 Route Information Preprocessing:
     * If the first value in the Route header field indicates this proxy,
     * the proxy MUST remove that value from the request.
     */

    route = (osip_route_t *) osip_list_get(msg->routes, 0);
    if (route && route->url && sip_is_local(ticket, route->url->host, route->url->port)) {
        osip_list_remove(msg->routes, 0);
        osip_route_free(route);
        if (proxy->debug > 5)
            Ns_Log(Debug, "removed Route header pointing to myself");
    }

    return NS_OK;
}


/*
 *
 * Route Information Postprocessing
 * 
 *
 * RFC 3261, Section 16.6 step 6
 * Proxy Behavior - Request Forwarding - Postprocess routing information
 *
 * If the copy contains a Route header field, the proxy MUST
 * inspect the URI in its first value.  If that URI does not
 * contain an lr parameter, the proxy MUST modify the copy as
 * follows:
 *
 * -  The proxy MUST place the Request-URI into the Route header
 *    field as the last value.
 *
 * -  The proxy MUST then place the first Route header field value
 *    into the Request-URI and remove that value from the Route
 *    header field.
 *
 *
 * RETURNS
 *	NS_OK on success
 */

static int proxy_route_postprocess(sip_ticket_t * ticket)
{
    osip_uri_t *url;
    osip_uri_param_t *param = 0;
    osip_route_t *route = 0, *route2 = 0;
    osip_message_t *msg = ticket->sipmsg;
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;

    if (!msg->routes || !(route = (osip_route_t *) osip_list_get(msg->routes, 0)))
        return NS_OK;

    /* check for non existing lr parameter */
    if (!osip_uri_uparam_get_byname(route->url, "lr", &param)) {

        /* push Request URI into Route header list at the last position */
        url = osip_message_get_uri(msg);
        osip_route_init(&route2);
        osip_uri_clone(url, &route2->url);
        osip_list_add(msg->routes, route2, -1);

        /* rewrite request URI to now topmost Route header */
        if (proxy->debug > 5)
            Ns_Log(Debug, "Route header w/o 'lr': rewriting request URI from %s to %s", url->host, route->url->host);
        osip_uri_free(url);
        osip_uri_clone(route->url, &(msg->req_uri));

        /* remove first Route header from list & free */
        osip_list_remove(msg->routes, 0);
        osip_route_free(route);
    }
    return NS_OK;
}


/*
 *
 * Add a Record-route header
 * 
 * RETURNS
 *	NS_OK on success
 */
static int proxy_rr_add(sip_ticket_t * ticket)
{
    int pos = 0;
    osip_uri_t *uri;
    osip_record_route_t *rr;
    osip_message_t *msg = ticket->sipmsg;

    /*
     * RFC 3261, Section 16.6 step 4
     * Proxy Behavior - Request Forwarding - Add a Record-route header
     */

    if (osip_record_route_init(&rr))
        return NS_OK;

    if (osip_uri_init(&uri)) {
        osip_record_route_free(rr);
        return NS_OK;
    }

    /* host name / IP / port */
    osip_uri_set_username(uri, osip_strdup(SIP_USER));
    osip_uri_set_host(uri, osip_strdup(ns_inet_ntoa(ticket->proxy->addr)));
    osip_uri_set_port(uri, int2str(ticket->proxy->port));
    osip_uri_uparam_add(uri, osip_strdup("lr"), NULL);
    osip_record_route_set_url(rr, uri);

    /* if it is a response, add in to the end of the list
     * (reverse order as in request!) 
     */

    if (MSG_IS_RESPONSE(ticket->sipmsg))
        pos = -1;

    /* insert into record-route list */
    osip_list_add(msg->record_routes, rr, pos);

    return NS_OK;
}


/*
 *
 * Purge Record-Route headers pointing to myself.
 * 
 * RETURNS
 *	NS_OK on success
 */
static int proxy_rr_del(sip_ticket_t * ticket)
{
    int last, i;
    osip_record_route_t *rr = NULL;
    osip_message_t *msg = ticket->sipmsg;

    if (!msg->record_routes)
        return NS_OK;
    last = osip_list_size(msg->record_routes) - 1;
    for (i = last; i >= 0; i--) {
        rr = (osip_record_route_t *) osip_list_get(msg->record_routes, i);
        if (rr && rr->url && sip_is_local(ticket, rr->url->host, rr->url->port)) {
            osip_list_remove(msg->record_routes, i);
            osip_record_route_free(rr);
            if (ticket->proxy->debug > 5)
                Ns_Log(Debug, "removed Record-Route header pointing to myself");
        }
    }
    return NS_OK;
}

static int sip_message_to_str(osip_message_t * sip, char **dest, int *len)
{
    int rc = osip_message_to_str(sip, dest, (unsigned int *) len);

    (*dest)[*len] = '\0';
    return rc;
}

/*
 * create a reply template from an given SIP request
 *
 * RETURNS a pointer to osip_message_t
 */
static osip_message_t *sip_message_reply(sip_ticket_t * ticket, int code)
{
    osip_message_t *request = ticket->sipmsg;
    osip_message_t *response;
    osip_via_t *via;
    char *tmp;
    int pos;

    osip_message_init(&response);
    response->message = NULL;
    osip_message_set_version(response, osip_strdup("SIP/2.0"));
    osip_message_set_status_code(response, code);
    osip_message_set_reason_phrase(response, osip_strdup(osip_message_get_reason(code)));

    if (!request->to) {
        Ns_Log(Error, "sip_make_template_reply: empty To in request header");
        return NULL;
    }

    if (!request->from) {
        Ns_Log(Error, "sip_make_template_reply: empty From in request header");
        return NULL;
    }

    osip_to_clone(request->to, &response->to);
    osip_from_clone(request->from, &response->from);

    /* via headers */
    pos = 0;
    while (!osip_list_eol(request->vias, pos)) {
        via = (osip_via_t *) osip_list_get(request->vias, pos);
        osip_via_to_str(via, &tmp);
        osip_message_set_via(response, tmp);
        osip_free(tmp);
        pos++;
    }
    osip_call_id_clone(request->call_id, &response->call_id);
    osip_cseq_clone(request->cseq, &response->cseq);
    return response;
}

/*
 *
 * send an proxy generated response back to the client.
 * Only errors are reported from the proxy itself.
 *  code =  SIP result code to deliver
 *
 * RETURNS
 *	NS_OK on success
 *	NS_ERROR on error
 */
static int sip_message_send(sip_ticket_t * ticket, int code)
{
    osip_message_t *response;
    osip_via_t *via;
    int port;
    char *buffer;
    int buflen;
    struct in_addr addr;

    /* create the response template */
    if ((response = sip_message_reply(ticket, code)) == NULL) {
        Ns_Log(Error, "sip_message_send: error in sip_make_template_reply");
        return NS_ERROR;
    }

    osip_message_get_via(response, 0, &via);
    if (via == NULL) {
        Ns_Log(Error, "sip_message_send: Cannot send response - no via field");
        return NS_ERROR;
    }

    /* name resolution */
    if (sipsock_resolve(via->host, &addr) == NS_ERROR) {
        Ns_Log(Error, "sip_message_send: cannot resolve via [%s]", via->host);
        return NS_ERROR;
    }

    if (sip_message_to_str(response, &buffer, &buflen)) {
        Ns_Log(Error, "sip_message_send: msg_2char failed");
        return NS_ERROR;
    }

    port = via->port ? atoi(via->port) : SIP_PORT;

    /* send to destination */
    sipsock_send(ticket, addr, port, buffer, buflen);

    /* free the resources */
    osip_message_free(response);
    osip_free(buffer);
    return NS_OK;
}

/*
 * check if a given host:port is local. I.e. its address is owned by our proxy
 *
 * RETURNS
 *	NS_TRUE if the given address is local
 *	NS_FALSE otherwise
 */
static int _sip_is_local(sip_ticket_t * ticket, struct in_addr addr, int port)
{
    if (ticket->proxy->port == port && ticket->proxy->addr.s_addr == addr.s_addr)
        return 1;

    return NS_FALSE;
}

static int sip_is_local(sip_ticket_t * ticket, char *shost, char *sport)
{
    int port;
    struct in_addr addr;

    if (!shost)
        return NS_ERROR;

    if (sipsock_resolve(shost, &addr) == NS_ERROR) {
        Ns_Log(Error, "sip_is_local: cannot resolve [%s]", shost);
        return NS_ERROR;
    }

    /* check the extracted VIA against my own host addresses */
    port = sport ? atoi(sport) : SIP_PORT;

    return _sip_is_local(ticket, addr, port);
}

/*
 * SIP_CALCULATE_BRANCH
 *
 * Calculates a branch parameter according to RFC3261 section 16.11
 *
 * RFC3261 section 16.11 recommends the following procedure:
 *   The stateless proxy MAY use any technique it likes to guarantee
 *   uniqueness of its branch IDs across transactions.  However, the
 *   following procedure is RECOMMENDED.  The proxy examines the
 *   branch ID in the topmost Via header field of the received
 *   request.  If it begins with the magic cookie, the first
 *   component of the branch ID of the outgoing request is computed
 *   as a hash of the received branch ID.  Otherwise, the first
 *   component of the branch ID is computed as a hash of the topmost
 *   Via, the tag in the To header field, the tag in the From header
 *   field, the Call-ID header field, the CSeq number (but not
 *   method), and the Request-URI from the received request.  One of
 *   these fields will always vary across two different
 *   transactions.
 *
 * The branch value will consist of:
 * - magic cookie
 * - unique calculated ID
 *
 * RETURNS
 *	NS_TRUE if existing Via with our branch found
 *	NS_FALSE if new branch is calculated
 */
static int sip_calculate_branch(sip_ticket_t * ticket, char *id)
{
    int magic_size = strlen(ticket->proxy->magic);
    osip_message_t *sip_msg = ticket->sipmsg;
    osip_uri_param_t *param = NULL;
    osip_call_id_t *call_id = NULL;
    unsigned char md5[17], hash[33] = "";
    char *tmp;
    osip_via_t *via;
    MD5_CTX ctx;

    /*
     * Examine topmost via and look for a magic cookie.
     */
    via = osip_list_get(sip_msg->vias, 0);
    osip_via_param_get_byname(via, "branch", &param);
    if (param && param->gvalue && !strncmp(param->gvalue, ticket->proxy->magic, magic_size)) {

        MD5Init(&ctx);
        MD5Update(&ctx, (unsigned char *) param->gvalue, strlen(param->gvalue));
        MD5Final(md5, &ctx);
        str2hex(md5, 16, hash);
        if (ticket->proxy->debug > 5)
            Ns_Log(Debug, "use existing branch for hash [%s]", hash);
        /* include the magic cookie */
        sprintf(id, "%s%s", ticket->proxy->magic, hash);
        return NS_TRUE;
    }

    /*
     * If I don't have a branch parameter in the existing topmost via,
     * then I need:
     *   - the topmost via
     *   - the tag in the To header field
     *   - the tag in the From header field
     *   - the Call-ID header field
     *   - the CSeq number (but not method)
     *   - the Request-URI from the received request
     */

    MD5Init(&ctx);

    /* topmost via */
    osip_via_to_str(via, &tmp);
    if (tmp) {
        MD5Update(&ctx, (unsigned char *) tmp, strlen(tmp));
        osip_free(tmp);
    }

    /* Tag in To header */
    osip_to_get_tag(sip_msg->to, &param);
    if (param && param->gvalue) {
        MD5Update(&ctx, (unsigned char *) param->gvalue, strlen(param->gvalue));
    }

    /* Tag in From header */
    osip_from_get_tag(sip_msg->from, &param);
    if (param && param->gvalue) {
        MD5Update(&ctx, (unsigned char *) param->gvalue, strlen(param->gvalue));
    }

    /* Call-ID */
    call_id = osip_message_get_call_id(sip_msg);
    osip_call_id_to_str(call_id, &tmp);
    if (tmp) {
        MD5Update(&ctx, (unsigned char *) tmp, strlen(tmp));
        osip_free(tmp);
    }

    /* CSeq number (but not method) */
    tmp = osip_cseq_get_number(sip_msg->cseq);
    if (tmp) {
        MD5Update(&ctx, (unsigned char *) tmp, strlen(tmp));
    }

    /* Request URI */
    osip_uri_to_str(sip_msg->req_uri, &tmp);
    if (tmp) {
        MD5Update(&ctx, (unsigned char *) tmp, strlen(tmp));
        osip_free(tmp);
    }

    MD5Final(md5, &ctx);
    str2hex(md5, 16, hash);

    if (ticket->proxy->debug > 5)
        Ns_Log(Debug, "non-existing branch -> branch hash [%s]", hash);

    /* include the magic cookie */
    sprintf(id, "%s%s", ticket->proxy->magic, hash);

    return NS_FALSE;
}

/*
 * do security and integrity checks on the received packet
 * (raw buffer, \0 terminated)
 *
 * RETURNS
 *	NS_OK if ok 
 * 	NS_ERROR if the packed did not pass the checks
 */
static int security_check_raw(char *sip_buffer, int size)
{
    char *p1 = NULL, *p2 = NULL;

    /*
     * empiric: size must be >= 16 bytes
     *   2 byte <CR><LF> packets have been seen in the wild
     */
    if (size < SEC_MIN_SIZE)
        return NS_ERROR;

    /*
     * make sure no line (up to the next CRLF) is longer than allowed
     * empiric: a line should not be longer than 256 characters
     * (libosip may die with "virtual memory exhausted" otherwise)
     * Ref: protos test suite c07-sip-r2.jar, test case 203
     */
    for (p1 = sip_buffer; p1 + SEC_LINE_SIZE < sip_buffer + size; p1 = p2 + 1) {
        p2 = strchr(p1, 10);
        if (!p2 || p2 - p1 > SEC_LINE_SIZE) {
            Ns_Log(Error, "security_check_raw: line too long or no CRLF found");
            return NS_ERROR;
        }
    }


    /* As libosip2 is *VERY* sensitive to corrupt input data, we need to
       do more stuff here. For example, libosip2 can be crashed (with a
       "<port_malloc.c> virtual memory exhausted" error - God knows why)
       by sending the following few bytes. It will die in osip_message_parse()
       ---BUFFER DUMP follows---
       6e 74 2f 38 30 30 30 0d 0a 61 3d 66 6d 74 70 3a nt/8000..a=fmtp:
       31 30 31 20 30 2d 31 35 0d 0a                   101 0-15..      
       ---end of BUFFER DUMP---

       By looking at the code in osip_message_parse.c, I'd guess it is
       the 'only one space present' that leads to a faulty size
       calculation (VERY BIG NUMBER), which in turn then dies inside 
       osip_malloc.
       So, we need at least 2 spaces to survive that code part of libosip2.
     */
    p1 = strchr(sip_buffer, ' ');
    if (p1 && p1 + 1 < sip_buffer + size) {
        p2 = strchr(p1 + 1, ' ');
    } else {
        Ns_Log(Error, "security_check_raw: found no space");
        return NS_ERROR;
    }
    if (!p2) {
        Ns_Log(Error, "security_check_raw: found only one space");
        return NS_ERROR;
    }

    /* TODO: still way to go here ... */
    return NS_OK;
}


/*
 * do security and integrity checks on the received packet
 * (parsed buffer)
 * 
 *  => Mandatory for ALL requests and responses
 *
 *  Call-ID                 c       r    m   m   m   m   m   m
 *  CSeq                    c       r    m   m   m   m   m   m
 *  From                    c       r    m   m   m   m   m   m
 *  To                      c(1)    r    m   m   m   m   m   m
 *  Via                     R      amr   m   m   m   m   m   m
 *
 * RETURNS
 *	NS_OK if ok 
 * 	NS_ERROR if the packed did not pass the checks
 *
RFC 3261            SIP: Session Initiation Protocol           June 2002

   Header field              where   proxy ACK BYE CAN INV OPT REG
   ______________________________________________________________
   Accept                     R            -   o   -   o   m*  o
   Accept                    2xx           -   -   -   o   m*  o
   Accept                    415           -   c   -   c   c   c
   Accept-Encoding            R            -   o   -   o   o   o
   Accept-Encoding           2xx           -   -   -   o   m*  o
   Accept-Encoding           415           -   c   -   c   c   c
   Accept-Language            R            -   o   -   o   o   o
   Accept-Language           2xx           -   -   -   o   m*  o
   Accept-Language           415           -   c   -   c   c   c
   Alert-Info                 R      ar    -   -   -   o   -   -
   Alert-Info                180     ar    -   -   -   o   -   -
   Allow                      R            -   o   -   o   o   o
   Allow                     2xx           -   o   -   m*  m*  o
   Allow                      r            -   o   -   o   o   o
   Allow                     405           -   m   -   m   m   m
   Authentication-Info       2xx           -   o   -   o   o   o
   Authorization              R            o   o   o   o   o   o
   Call-ID                    c       r    m   m   m   m   m   m
   Call-Info                         ar    -   -   -   o   o   o
   Contact                    R            o   -   -   m   o   o
   Contact                   1xx           -   -   -   o   -   -
   Contact                   2xx           -   -   -   m   o   o
   Contact                   3xx      d    -   o   -   o   o   o
   Contact                   485           -   o   -   o   o   o
   Content-Disposition                     o   o   -   o   o   o
   Content-Encoding                        o   o   -   o   o   o
   Content-Language                        o   o   -   o   o   o
   Content-Length                    ar    t   t   t   t   t   t
   Content-Type                            *   *   -   *   *   *
   CSeq                       c       r    m   m   m   m   m   m
   Date                               a    o   o   o   o   o   o
   Error-Info              300-699    a    -   o   o   o   o   o
   Expires                                 -   -   -   o   -   o
   From                       c       r    m   m   m   m   m   m
   In-Reply-To                R            -   -   -   o   -   -
   Max-Forwards               R      amr   m   m   m   m   m   m
   Min-Expires               423           -   -   -   -   -   m
   MIME-Version                            o   o   -   o   o   o
   Organization                      ar    -   -   -   o   o   o
   Priority                    R     ar    -   -   -   o   -   -
   Proxy-Authenticate         407    ar    -   m   -   m   m   m
   Proxy-Authenticate         401    ar    -   o   o   o   o   o
   Proxy-Authorization         R     dr    o   o   -   o   o   o
   Proxy-Require               R     ar    -   o   -   o   o   o
   Record-Route                R     ar    o   o   o   o   o   -
   Record-Route             2xx,18x  mr    -   o   o   o   o   -
   Reply-To                                -   -   -   o   -   -
   Require                           ar    -   c   -   c   c   c
   Retry-After              404,413,       -   o   o   o   o   o
                            480,486        -   o   o   o   o   o
                            500,503        -   o   o   o   o   o
                            600,603        -   o   o   o   o   o
   Route                       R     adr   c   c   c   c   c   c
   Server                      r           -   o   o   o   o   o
   Subject                     R           -   -   -   o   -   -
   Supported                   R           -   o   o   m*  o   o
   Supported                  2xx          -   o   o   m*  m*  o
   Timestamp                               o   o   o   o   o   o
   To                        c(1)     r    m   m   m   m   m   m
   Unsupported                420          -   m   -   m   m   m
   User-Agent                              o   o   o   o   o   o
   Via                         R     amr   m   m   m   m   m   m
   Via                        rc     dr    m   m   m   m   m   m
   Warning                     r           -   o   o   o   o   o
   WWW-Authenticate           401    ar    -   m   -   m   m   m
   WWW-Authenticate           407    ar    -   o   -   o   o   o

 */

static int security_check_sip(sip_ticket_t * ticket)
{
    osip_message_t *sip = ticket->sipmsg;

    if (MSG_IS_REQUEST(sip)) {
        /* check for existing SIP URI in request */
        if (!sip->req_uri || !sip->req_uri->scheme) {
            Ns_Log(Error, "security check failed: NULL SIP URI");
            return NS_ERROR;
        }

        /* check SIP URI scheme */
        if (osip_strcasecmp(sip->req_uri->scheme, "sip")) {
            Ns_Log(Error, "security check failed: unknown scheme: %s", sip->req_uri->scheme);
            return NS_ERROR;
        }
    }

    /*
     * Check existence of mandatory headers
     *
     */

    /* check for existing Call-ID header */
    if (!sip->call_id || (!sip->call_id->number && !sip->call_id->host)) {
        Ns_Log(Error, "security check failed: NULL Call-Id Header");
        return NS_ERROR;
    }

    /* check for existing CSeq header */
    if (!sip->cseq || !sip->cseq->method || !sip->cseq->number) {
        Ns_Log(Error, "security check failed: NULL CSeq Header");
        return NS_ERROR;
    }

    /* check for existing To: header */
    if (!sip->to || !sip->to->url || !sip->to->url->host) {
        Ns_Log(Error, "security check failed: NULL To Header");
        return NS_ERROR;
    }

    /* check for existing From: header */
    if (!sip->from || !sip->from->url || !sip->from->url->host) {
        Ns_Log(Error, "security check failed: NULL From Header");
        return NS_ERROR;
    }

    /* check for existing Via: header list */
    if (!sip->vias) {
        Ns_Log(Error, "security check failed: No Via Headers");
        return NS_ERROR;
    }
    /* TODO: still way to go here ... */
    return NS_OK;
}

/*
 * sends an UDP datagram to the specified destination
 *
 * RETURNS
 *      NS_OK on success
 *      NS_ERROR on error
 */
static int sipsock_send(sip_ticket_t * ticket, struct in_addr addr, int port, char *buffer, int size)
{
    struct sockaddr_in sa;
    sip_proxy_t *proxy = (sip_proxy_t *) ticket->proxy;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr.s_addr, &addr, sizeof(struct in_addr));

    if (proxy->debug > 7)
        Ns_Log(Debug, "sipsock_send: UDP packet %d bytes to %s: %i\n%s", size, ns_inet_ntoa(addr), port, buffer);

    if (sendto(proxy->sock, buffer, size, 0, (const struct sockaddr *) &sa, (socklen_t) sizeof(sa)) == -1) {
        Ns_Log(Error, "sendto() [%s:%i size=%i] call failed: %s", ns_inet_ntoa(addr), port, size, strerror(errno));
        return NS_ERROR;
    }
    return NS_OK;
}

/*
 * resolve a hostname and return in_addr
 * handles its own little DNS cache.
 *
 * RETURNS
 *      NS_OK on success
 *      NS_ERROR on failure
 */

static int sipsock_resolve(char *host, struct in_addr *addr)
{
    struct sockaddr_in sa;

    if (!host)
        host = Ns_InfoHostname();
    if (Ns_GetSockAddr(&sa, host, 0) != NS_OK)
        return NS_ERROR;
    *addr = sa.sin_addr;
    return NS_OK;
}

/*
 * convert binary string tino hex string
 *
 * RETURNS
 *      output buffer
 */

static unsigned char *str2hex(unsigned char *from, int size, unsigned char *to)
{
    static char hex[] = "0123456789ABCDEF";
    int i, j;

    for (j = 0, i = 0; i < size; i++) {
        to[j++] = hex[(from[i] >> 4) & 0x0F];
        to[j++] = hex[from[i] & 0x0F];
    }
    to[j] = 0;
    return to;
}

static char *int2str(int num)
{
    char tmp[32];
    sprintf(tmp, "%i", num);
    return osip_strdup(tmp);
}
