// Formatted using
//   clang-format -i sample_formatted_code.do_not_merge.c

// SortIncludes
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "sample.llvm.h"

//--- Line Length ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#Line-length
// ColumnLimit: 80
// ContinuationIndentWidth: 8
static int some_really_long_variable_definition_that_is_80_chars_long = 1234567;
static int some_long_variable_definition_that_wraps_and_continues_at_next_line =
        1234567890123;

//--- Indent ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#Indent
// IndentWidth: 4
// AlignAfterOpenBracket
int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_eth, tv->sc_perf_pca);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
}

//--- Braces ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#Braces
int SomeFunction(void)
{
    DoSomething();
}

void brace_style()
{
    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (this) {
        DoThis();
    } else {
        DoThat();
    }
}

//--- Flow ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#Flow
void if_style()
{
    // AllowShortIfStatementsOnASingleLine
    if (a)
        b = a; // <- right

    if (a)
        b();
    else
        c();

    if (a)
        return;
    else {
        return;
    }

    if (a)
        return;
}

void for_loop_style()
{
    // for (no parens, would fit on one line if wanted)
    for (int i = 0; i < 32; ++i)
        i += 1;

    // for (parens, would fit on one line if wanted)
    for (int i = 0; i < 32; ++i) {
        i += 1;
    }

    // for
    for (int i : 0; i < some_max_number; ++i) {
        int b = someFunctionCall(int16_t)*LongNameForParameter2,
                (float *)LongNameForParameter2);
        s.second++;
    }
}

void while_style()
{
    // AllowShortBlocksOnASingleLine
    while (some) {
    }
    while (some) {
        continue;
    }

    // AllowShortLoopsOnASingleLine
    while (true)
        continue;
}

void do_while_style()
{
    do {
        a++;
    } while (a == 0);

    do {
        if (a)
            a--;
        else
            a++;
    } while (false);
}

// functions - Functions should have the opening bracket on a newline:
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#curly-braces-brackets
int some_function()
{
    int a = 13;
    return a * a;
}

// BraceWrapping:SplitEmptyFunction if BreakBeforeBraces: Custom
void empty_function(void)
{
}

// AllowShortFunctionsOnASingleLine
int short_function(void)
{
    return 1;
}

// all params fit on continuation line
// AlignAfterOpenBracket
static void function_with_params_split(
        const char *key, json_t *value, idmef_alert_t *alert)
{
    bla();
}

// params too long to fit on one continuation line, broken apart over multiple
// lines
// AlignAfterOpenBracket
int some_function_with_parms_split(uint32_t *LongNameForParameter1,
        double *LongNameForParameter2, const float *LongNameForParameter3,
        const struct SomeStructWithALongName LongNameForParameter4)
{
    int a = 3;
    return a * a;
}

//--- switch ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#switch-statements
void switch_style()
{
    // IndentCaseBlocks
    // IndentCaseLabels

    // Switch statements are indented like in the following example, so the
    // 'case' is indented from the switch
    switch (ntohs(p->ethh->eth_type)) {
        case ETHERNET_TYPE_IP:
            DecodeIPV4(tv, dtv, p, pkt + ETHERNET_HEADER_LEN,
                    len - ETHERNET_HEADER_LEN, pq);
            break;
    }

    // Fall through cases will be commented with /* fall through */. E.g.:
    switch (suri->run_mode) {
        case RUNMODE_PCAP_DEV:
        case RUNMODE_AFP_DEV:
        case RUNMODE_PFRING:
            /* find payload for interface and use it */
            default_packet_size = GetIfaceMaxPacketSize(suri->pcap_dev);
            if (default_packet_size)
                break;
            /* fall through */
        default:
            default_packet_size = DEFAULT_PACKET_SIZE;
    }

    // BraceWrapping:AfterCaseLabel if BreakBeforeBraces: Custom
    // AllowShortCaseLabelsOnASingleLine
    switch (a) {
        case 13: {
            int a = bla();
            break;
        }
        case 15:
            blu();
            break;
        default:
            gugus();
    }
}

//--- goto ---
// https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Coding_Style#goto
void goto_style()
{
    DetectFileextData *fileext = NULL;

    fileext = SCMalloc(sizeof(DetectFileextData));
    if (unlikely(fileext == NULL))
        goto error;

    memset(fileext, 0x00, sizeof(DetectFileextData));

    if (DetectContentDataParse("fileext", str, &fileext->ext, &fileext->len,
                &fileext->flags) == -1) {
        goto error;
    }

    return fileext;

error:
    if (fileext != NULL)
        DetectFileextFree(fileext);
    return NULL;
}

int goto_style_nested()
{
    // IndentGotoLabels
    if (foo()) {
    label1:
        bar();
    }

label2:
    return 1;
}

//--- ternary style ---
// BreakBeforeTernaryOperators - whether ? and : are on next line
void ternary_op_style()
{
    // fits on one line
    float droppy = a > 0 ? a * 100 : 0;

    // split across lines - Continuation indent based on '=' fits line
    float drop_percent = likely(ptv->last_stats64.ps_recv > 0)
                                 ? (((float)ptv->last_stats64.ps_drop) /
                                           (float)ptv->last_stats64.ps_recv) *
                                           100
                                 : 0;

    // split across lines - Continuation indent based on '=' would be too long,
    // uses normal continuation indent based on start of line
    float drop_percent_a_bit_longer =
            likely(ptv->last_stats64.ps_recv > 0)
                    ? (((float)ptv->last_stats64.ps_drop) /
                              (float)ptv->last_stats64.ps_recv) *
                              100
                    : 0;
}

//--- enum style ---
// clang 11: AllowShortEnumsOnASingleLine
// clang < 11:
// - merges short enums on one line if BraceWrapping: AfterEnum: false
// - one-value-by-line if BraceWrapping: AfterEnum: true
enum Gugus { bla, bli, blu };

enum ThisIsTooLongForOneLine {
    blablablablablablablabla,
    blibliblibliblibliblibli,
    blublublublublublublublu
};

enum { A, B } myEnum;

// trailing comma forces one-value-by-line
enum {
    NFS_DECODER_EVENT_EMPTY_MESSAGE,
};

//--- union style ---
typedef union {
    int gugus;
} Bla;

union bla {
    int gugus;
};

// --- struct style ---
struct bla {
    int gugus;
};

struct bla_ {
    int gugus;
} Bla;

typedef struct bla_ {
    int gugus;
} Bla;

//--- Alignment ---
struct bla {
    // AlignConsecutiveDeclarations
    // AlignTrailingComments
    int a;       /* comment */
    unsigned bb; /* comment */
    int *ccc;    /* comment */
};

// pointers
// DerivePointerAlignment
// PointerAlignment
void *ptr;
void f(int *a, const char *b);
void (*foo)(int *);

void alignment()
{
    // multiple consecutive vars (comments and vars can be aligned)
    // AlignConsecutiveAssignments
    // AlignConsecutiveDeclarations
    // AlignTrailingComments
    int a = 13;           /* comment */
    int32_t abc = 1312;   /* comment */
    int abcdefghikl = 13; /* comment */

    // AlwaysBreakBeforeMultilineStrings
    aaaa = "bbbb"
           "ccc";

    //--- variable init continuation behaviour
    // Cpp11BracedListStyle impacts if space at beginning and end of brace
    // e.g. false: Bla bla[] = { 1, 2, 3 };
    //      true:  Bla bla[] = {1, 2, 3};
    // Note, the different indentation of continuation line:
    //  - Cpp11BracedListStyle:false does NOT use ContinuationIndentWidth (8)
    //    but rather the regular IndentWidth (4)! Bug? Feature?
    //  - Cpp11BracedListStyle:true uses ContinuationIndentWidth (8)
    int list[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int list[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
    int list[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22};
    PcapStats64 last = {0, 1234, 8765};
    // trailing comma forces one-value-by-line
    PcapStats64 trailing_comma = {
            0,
            1234,
            8765,
    };
    struct pcap_stat current = {12, 2345, 9876, 1345};
    struct pcap_stat current = {
            12, 2345, 9876, 1345, 333, 444, 5555, 66666, 7777777};
    current = {12, 2345, 9876, 1345, 333, 444, 5555, 66666, 7777777, 888888,
            9999999};

    //--- designated initializer continuation behaviour
    // Current clang-format disables BinPacking for designated intializers when
    // continuing on more than one line.
    PcapStats64 last = {.ps_recv = 0, .ps_drop = 1234, .ps_ifdrop = 8765};
    // Cpp11BracedListStyle:false puts end brace onto separate line iff
    // continuation line can hold all intializers. Bug? Feature?
    struct pcap_stat current = {
            .ps_recv = 12, .ps_drop = 2345, .ps_ifdrop = 9876, .ps_what = 134};
    pcap_stat current = {
            .ps_recv = 12, .ps_drop = 2345, .ps_ifdrop = 9876, .ps_what = 134};
    // One designated initializer per line if it does not fit into one
    // continuation line as BinPacking is disabled for designated intializer.
    struct pcap_stat current = {.ps_recv = 12,
            .ps_drop = 2345,
            .ps_ifdrop = 9876,
            .ps_what = 1345,
            .ps_more = 333};
    current = {.ps_recv = 12,
            .ps_drop = 2345,
            .ps_ifdrop = 9876,
            .ps_what = 1345,
            .ps_more = 333};

    // function call continuation
    function_call(
            with, many, params, that, will spill, over, eventually, iff, max);
    function_call(with, many, params, that, will spill, over, eventually, iff,
            we, keep, on, adding);
}

struct Bitfields {
    // clang 11: AlignConsecutiveBitFields
    int aaaa : 1;
    int b : 12;
    int ccc : 8;
};

static void wrapping_literals()
{
    // string literal is too long. Continuation is from "string literal start",
    // not ContinuationIndentWith, due to reasons?
    SCLogInfo("running in 'auto' checksum mode. Detection of interface "
              "state will require " xstr(CHECKSUM_SAMPLE_COUNT) " packets");

    // Same as above but with additional parameter using ContinuationIndentWith
    SCLogInfo("running in 'auto' checksum mode. Detection of interface "
              "state will require " xstr(CHECKSUM_SAMPLE_COUNT) " packets %d",
            someValue);

    // Just params use ContinuationIndentWith
    SCLogError(SC_ERR_STAT, "(%s) Failed to get pcap_stats: %s", tv->name,
            pcap_geterr(ptv->pcap_handle));

    // string literal param that fits on continuation line uses
    // ContinuationIndentWith
    SCLogError(SC_ERR_INITIALIZATION,
            "Error getting context for Prelude. \"initdata\" argument NULL");
    if (unlikely(initdata == NULL)) {
        // string literal param does not fit on continuation line
        // Continuation is from "string literal start", not
        // ContinuationIndentWith, due to reasons
        SCLogError(SC_ERR_INITIALIZATION, "Error getting context for Prelude.  "
                                          "\"initdata\" argument NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    // function call inside if needs breaking apart and uses
    // ContinuationIndentWith starting at function. Nice.
    if (DetectContentDataParse("fileext", str, &fileext->ext, &fileext->len,
                &fileext->flags) == -1) {
        goto error;
    }
}

//--- foreach handling as "for loop" ---
void foreach_handling()
{
    // ForEachMacros

    // json_object_foreach and json_array_foreach are "foreach" functions
    if (json_is_object(value)) {
        json_object_foreach (value, key_js, value_js) {
            bla()
        }
    } else if (json_is_array(value)) {
        json_array_foreach (value, index, value_js) {
            bla()
        }
    } else if (json_is_integer(value)) {
        ret = AddIntData(alert, key, json_integer_value(value));
    }

    // These are foreach macros but apart from the odd exception, they
    // use start parens on next line if they are used in code.
    // It would be trivial to also handle them like "for loops"

    // tree.h: SLIST_FOREACH, SLIST_FOREACH_PREVPTR, LIST_FOREACH,
    // SIMPLEQ_FOREACH, TAILQ_FOREACH, TAILQ_FOREACH_SAFE,
    // TAILQ_FOREACH_REVERSE, CIRCLEQ_FOREACH, CIRCLEQ_FOREACH_REVERSE,
    // CIRCLEQ_FOREACH_SAFE, CIRCLEQ_FOREACH_REVERSE_SAFE

    TAILQ_FOREACH(child, &node->head, next)
    {
        name[level] = SCStrdup(child->name);
        /* ... */
        SCFree(name[level]);
    }

    // queue.h: SPLAY_FOREACH, RB_FOREACH, RB_FOREACH_FROM, RB_FOREACH_SAFE,
    // RB_FOREACH_REVERSE, RB_FOREACH_REVERSE_FROM, RB_FOREACH_REVERSE_SAFE
    RB_FOREACH_REVERSE_FROM(tree_seg, TCPSEG, s)
    {
        if (tree_seg == seg)
            continue;
        /* ... */
    }
}

//--- comment wrapping ---
void multi_line_comments()
{
    // ReflowComments: false does not trim comments to ColumnLimit chars

    // TODO: This is a long comment that allows you to understand how long
    // comments will be trimmed. Here should be deep thought but it's just not
    // right time for this

    /* TODO: This is a long comment that allows you to understand how long
     * comments will be trimmed. Here should be deep thought but it's just not
     * right time for this
     */
}

//--- macros ---
#define BIT_MASK 0xDEADBEAF

// alignment of macro values
// AlignConsecutiveMacros
#define ACTION_ALERT       0x01
#define ACTION_DROP        0x02
#define ACTION_REJECT      0x04
#define ACTION_REJECT_DST  0x08
#define ACTION_REJECT_BOTH 0x10
#define ACTION_PASS        0x20

// multi-line macros (alignment of backslash can be changed)
// AlignEscapedNewlines: DontAlign, Left, Right
#define MULTILINE_DEF(a, b)         \
    if ((a) > 2) {                  \
        auto temp = (b) / 2;        \
        (b) += 10;                  \
        someFunctionCall((a), (b)); \
    }

// Formatting of macros cannot be separately configured
#define TAILQ_INIT(head)                       \
    do {                                       \
        (head)->tqh_first = NULL;              \
        (head)->tqh_last = &(head)->tqh_first; \
    } while (0)

#define SLIST_INIT(head)                     \
    {                                        \
        SLIST_FIRST(head) = SLIST_END(head); \
    }

#define APP_LAYER_INCOMPLETE(c, n) \
    (AppLayerResult)               \
    {                              \
        1, (c), (n)                \
    }
// but...
#define APP_LAYER_INCOMPLETE(c, n) ((AppLayerResult){1, (c), (n)})

// Only solution is to clang-format on/off if it does not please
/* clang-format off */
#define APP_LAYER_INCOMPLETE(c, n) (AppLayerResult){1, (c), (n)}
/* clang-format on */

//--- disabling formatting ---
// yes, it formats/indents the actual clang-format off/on comment
void disable_formatting()
{
    /* clang-format off */
int a = 16;
int32_t b = whatever(  "I wanna have my own style"
                     , "with some"
, "params all crooked");
    /* clang-format on */

    // this is formatted again:
    int32_t b = whatever(
            "I wanna have my own style", "with some", "params all crooked");
}

//--- EOF ---
// clang-format removes trailing empty lines
