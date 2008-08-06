#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* a is ... than b */
enum {
    ADDRESS_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /* smaller              [aaa] [bbb] */
    ADDRESS_LE,      /* smaller with overlap [aa[bab]bb] */
    ADDRESS_EQ,      /* exactly equal        [abababab]  */
    ADDRESS_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GE,      /* bigger with overlap  [bb[aba]aa] */
    ADDRESS_GT,      /* bigger               [bbb] [aaa] */
};

typedef struct DetectAddressData_ {
    u_int8_t family;
    u_int32_t ip[4];
    u_int32_t ip2[4];
} DetectAddressData;

typedef struct DetectAddressGroup_ {
    /* address data for this group */
    DetectAddressData *ad;

    /* XXX ptr to rules, or PortGroup or whatever */


    /* double linked list */
    struct DetectAddressGroup_ *prev;
    struct DetectAddressGroup_ *next;

} DetectAddressGroup;

typedef struct DetectAddressGroupsHead_ {
    DetectAddressGroup *ipv4_head;
    DetectAddressGroup *ipv6_head;
} DetectAddressGroupsHead;

/* prototypes */
void DetectAddressRegister (void);
DetectAddressGroupsHead *DetectAddressGroupsHeadInit();
void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *);

#endif /* __DETECT_ADDRESS_H__ */

