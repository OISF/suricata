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

#define ADDRESS_FLAG_ANY 0x1
#define ADDRESS_FLAG_NOT 0x2

#define ADDRESS_GROUP_SIGGROUPHEAD_COPY  0x01
#define ADDRESS_GROUP_PORTS_COPY         0x02
#define ADDRESS_GROUP_PORTS_NOTUNIQ      0x04

typedef struct DetectAddressData_ {
    /* XXX convert to use a Address datatype to replace family, ip,ip2*/
    u_int8_t family;
    u_int32_t ip[4];
    u_int32_t ip2[4];
    u_int8_t flags;
} DetectAddressData;

typedef struct DetectAddressGroup_ {
    /* address data for this group */
    DetectAddressData *ad;

    /* XXX ptr to rules, or PortGroup or whatever */
    struct DetectAddressGroupsHead_ *dst_gh;
    struct DetectPort_ *port;

    /* signatures that belong in this group */
    struct _SigGroupHead *sh;
    u_int8_t flags;

    /* double linked list */
    struct DetectAddressGroup_ *prev;
    struct DetectAddressGroup_ *next;

    u_int32_t cnt;
} DetectAddressGroup;

typedef struct DetectAddressGroupsHead_ {
    DetectAddressGroup *any_head;
    DetectAddressGroup *ipv4_head;
    DetectAddressGroup *ipv6_head;
} DetectAddressGroupsHead;

/* prototypes */
void DetectAddressRegister (void);
DetectAddressGroupsHead *DetectAddressGroupsHeadInit();
void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *);
void DetectAddressGroupsHeadCleanup(DetectAddressGroupsHead *);
DetectAddressData *DetectAddressDataInit(void);
void DetectAddressDataFree(DetectAddressData *);
void DetectAddressDataPrint(DetectAddressData *);
DetectAddressData *DetectAddressDataCopy(DetectAddressData *);
int DetectAddressGroupSetup(DetectAddressGroupsHead *, char *);
int DetectAddressCmp(DetectAddressData *, DetectAddressData *);
DetectAddressData *DetectAddressParse(char *);
DetectAddressGroup *DetectAddressLookupGroup(DetectAddressGroupsHead *, Address *);
int DetectAddressGroupParse(DetectAddressGroupsHead *, char *);
DetectAddressGroup *DetectAddressGroupInit(void);
int DetectAddressGroupAdd(DetectAddressGroup **, DetectAddressGroup *);
DetectAddressGroup *DetectAddressGroupLookup(DetectAddressGroup *, DetectAddressData *);
void DetectAddressGroupPrintList(DetectAddressGroup *);
void DetectAddressGroupFree(DetectAddressGroup *);
int DetectAddressGroupInsert(DetectAddressGroupsHead *, DetectAddressGroup *);
void DetectAddressGroupPrintMemory(void);
void DetectAddressGroupCleanupList (DetectAddressGroup *);
int DetectAddressGroupJoin(DetectAddressGroup *target, DetectAddressGroup *source);

#endif /* __DETECT_ADDRESS_H__ */

