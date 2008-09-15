#ifndef __DETECT_PORT_H__
#define __DETECT_PORT_H__

/* a is ... than b */
enum {
    PORT_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    PORT_LT,      /* smaller              [aaa] [bbb] */
    PORT_LE,      /* smaller with overlap [aa[bab]bb] */
    PORT_EQ,      /* exactly equal        [abababab]  */
    PORT_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    PORT_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    PORT_GE,      /* bigger with overlap  [bb[aba]aa] */
    PORT_GT,      /* bigger               [bbb] [aaa] */
};

#define PORT_FLAG_ANY 0x1
#define PORT_FLAG_NOT 0x2

#define PORT_SIGGROUPHEAD_COPY 0x04

typedef struct DetectPort_ {
    u_int8_t flags;

    u_int16_t port;
    u_int16_t port2;

    /* signatures that belong in this group */
    struct _SigGroupHead *sh;

    /* double linked list */
    union {
        struct DetectPort_ *prev;
        struct DetectPort_ *hnext;
    };
    struct DetectPort_ *next;

} DetectPort;

/* prototypes */
void DetectPortRegister (void);

int DetectPortParse(DetectPort **head, char *str);

DetectPort *DetectPortCopy(DetectPort *);
DetectPort *DetectPortCopySingle(DetectPort *);
int DetectPortInsertCopy(DetectPort **, DetectPort *);
int DetectPortInsert(DetectPort **, DetectPort *);
void DetectPortCleanupList (DetectPort *head);

DetectPort *DetectPortLookup(DetectPort *head, DetectPort *dp);
int DetectPortAdd(DetectPort **head, DetectPort *dp);

DetectPort *DetectPortLookupGroup(DetectPort *dp, u_int16_t port);

void DetectPortPrintMemory(void);

DetectPort *DetectPortHashLookup(DetectPort *p);
DetectPort **DetectPortHashGetPtr(void);
DetectPort *DetectPortHashGetListPtr(void);
u_int32_t DetectPortHashGetSize(void);
int DetectPortHashInit(void);
void DetectPortHashFree(void);
int DetectPortHashAdd(DetectPort *p);
void DetectPortHashReset(void);

#endif /* __DETECT_PORT_H__ */

