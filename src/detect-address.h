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

    /* signatures that belong in this group */
    struct _SigGroupHead *sh;

    /* double linked list */
    struct DetectAddressGroup_ *prev;
    struct DetectAddressGroup_ *next;

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
int DetectAddressGroupInsert(DetectAddressGroupsHead *, DetectAddressData *);
int DetectAddressGroupSetup(DetectAddressGroupsHead *, char *);
int DetectAddressCmp(DetectAddressData *, DetectAddressData *);
DetectAddressData *DetectAddressParse(char *);
DetectAddressGroup *DetectAddressLookupGroup(DetectAddressGroupsHead *, Address *);
int DetectAddressGroupParse(DetectAddressGroupsHead *, char *);
DetectAddressGroup *DetectAddressGroupInit(void);
int DetectAddressGroupAppend(DetectAddressGroup **head, DetectAddressGroup *ag);
DetectAddressGroup *DetectAddressGroupLookup(DetectAddressGroup *head, DetectAddressData *ad);
void DetectAddressGroupPrintList(DetectAddressGroup *);

#endif /* __DETECT_ADDRESS_H__ */

