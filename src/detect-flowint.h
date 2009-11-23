#ifndef __DETECT_FLOWINT_H__
#define __DETECT_FLOWINT_H__

/** Flowint operations allowed */
enum {
    /** Changing integer values */
    FLOWINT_MODIFIER_SET,
    FLOWINT_MODIFIER_ADD,
    FLOWINT_MODIFIER_SUB,

    /** Comparing integer values */
    FLOWINT_MODIFIER_LT,
    FLOWINT_MODIFIER_LE,
    FLOWINT_MODIFIER_EQ,
    FLOWINT_MODIFIER_NE,
    FLOWINT_MODIFIER_GE,
    FLOWINT_MODIFIER_GT,
    /** Checking if a var isset (keyword isset)*/
    FLOWINT_MODIFIER_IS,

    FLOWINT_MODIFIER_UNKNOWN
};

/** The target can be a value, or another variable arleady declared */
enum {
    FLOWINT_TARGET_VAL,
    FLOWINT_TARGET_VAR,
    FLOWINT_TARGET_SELF,
    FLOWINT_TARGET_UNKNOWN
};

/** If the target is another var, get the name and the idx */
typedef struct TargetVar_ {
    uint16_t idx;
    char *name;
} TargetVar;

/** Context data for flowint vars */
typedef struct DetectFlowintData_ {
    char *name;                 /* This is the main var we are going to use
                                 * against the target */
    uint16_t idx;

    uint8_t modifier;           /* The modifier/operation/condition we are
                                 * going to execute */

    uint8_t targettype;
    union {
        uint32_t value;         /* the target value */
        TargetVar tvar;         /* or the target var */
    } target;
} DetectFlowintData;

/* prototypes */
void DetectFlowintRegister (void);

#endif /* __DETECT_FLOWINT_H__ */

