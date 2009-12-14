/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_CLASSIFICATION_CONFIG_H__
#define __UTIL_CLASSIFICATION_CONFIG_H__

/**
 * \brief Container for a Classtype from the Classification.config file.
 */
typedef struct SCClassConfClasstype_ {
    /* The classtype name.  This is the primary key for a Classification. */
    char *classtype;

    /* Description for a classification.  Would be used while printing out
     * the classification info for a Signature, by the fast-log module. */
    char *classtype_desc;

    /* The priority this classification type carries */
    int priority;
} SCClassConfClasstype;

SCClassConfClasstype *SCClassConfAllocClasstype(const char *, const char *,
                                                    int);
void SCClassConfDeAllocClasstype(SCClassConfClasstype *);
void SCClassConfLoadClassficationConfigFile(DetectEngineCtx *);
void SCClassConfRegisterTests(void);

void SCClassConfGenerateValidDummyClassConfigFD01(void);
void SCClassConfGenerateInValidDummyClassConfigFD02(void);
void SCClassConfGenerateInValidDummyClassConfigFD03(void);
void SCClassConfDeleteDummyClassificationConfigFD(void);

#endif /* __UTIL_CLASSIFICATION_CONFIG_H__ */
