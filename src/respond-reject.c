/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* RespondReject is a threaded wrapper for sending Rejects 
 *
 */

#include <pthread.h>
#include <sys/signal.h>
#include <libnet.h>

#include "vips.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "action-globals.h"
#include "respond-reject.h"
#include "respond-reject-libnet11.h"

int RejectSendIPv4TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv4ICMP(ThreadVars *, Packet *, void *);
int RejectSendIPv6TCP(ThreadVars *, Packet *, void *);
int RejectSendIPv6ICMP(ThreadVars *, Packet *, void *);

void TmModuleRespondRejectRegister (void) {

    tmm_modules[TMM_RESPONDREJECT].name = "RespondReject";
    tmm_modules[TMM_RESPONDREJECT].Init = NULL;
    tmm_modules[TMM_RESPONDREJECT].Func = RespondRejectFunc;
    tmm_modules[TMM_RESPONDREJECT].Deinit = NULL;
    tmm_modules[TMM_RESPONDREJECT].RegisterTests = NULL;
}

int RespondRejectFunc(ThreadVars *tv, Packet *p, void *data) {
 
    /* ACTION_REJECT defaults to rejecting the SRC */ 
    if(p->action != ACTION_REJECT && p->action != ACTION_REJECT_DST &&
       p->action != ACTION_REJECT_BOTH) {
        return 0;
     }
    
     if(PKT_IS_IPV4(p)){
         if(PKT_IS_TCP(p)){   
             return RejectSendIPv4TCP(tv, p, data);
           } else if(PKT_IS_UDP(p)){
               return RejectSendIPv4ICMP(tv, p, data);
           } else{
               return 0;
           }
         } else if (PKT_IS_IPV6(p)) {
             if(PKT_IS_TCP(p)){
                 return RejectSendIPv6TCP(tv, p, data);
             } else if(PKT_IS_UDP(p)){
                 return RejectSendIPv6ICMP(tv, p, data);
             } else{
                 return 0;
             }
         } else{
             printf ("wtf? packet is not ipv4 or ipv6 returning\n");
             return 0;
           }
}

int RejectSendIPv4TCP(ThreadVars *tv, Packet *p, void *data){
    if(p->action == ACTION_REJECT){
        return RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC);
     } else if(p->action == ACTION_REJECT_DST){
         return RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST);
     } else if(p->action == ACTION_REJECT_BOTH){
         if(RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_SRC) == 0 && 
	    RejectSendLibnet11L3IPv4TCP(tv, p, data, REJECT_DIR_DST) == 0){
             return 0;
          } else {
              return 1;
          }
     }
     return 0;
}
int RejectSendIPv4ICMP(ThreadVars *tv, Packet *p, void *data){
    printf ("we would send a ipv4 icmp reset here\n");
    return 1;
}
int RejectSendIPv6TCP(ThreadVars *tv, Packet *p, void *data){
    printf ("we would send a ipv6 tcp reset here\n");
    return 1;
}
int RejectSendIPv6ICMP(ThreadVars *tv, Packet *p, void *data){
    printf ("we would send a ipv6 icmp reset here\n");
    return 1;
}

