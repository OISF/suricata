/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "packet-queue.h"
#include "tm-modules.h"

void TmModuleDebugList(void) {
    TmModule *t;
    uint16_t i;

    printf("TmModuleDebugList: start\n");
    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        printf("TmModuleDebugList: %s:%p\n", t->name, t->Func);
    }
    printf("TmModuleDebugList: end\n");
}

/** \brief get a tm module ptr by name
 *  \param name name string
 *  \retval ptr to the module or NULL */
TmModule *TmModuleGetByName(char *name) {
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (strcmp(t->name, name) == 0)
            return t;
    }

    return NULL;
}

/** \brief register all unittests for the tm modules */
void TmModuleRegisterTests(void) {
#ifdef UNITTESTS
    TmModule *t;
    uint16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->name == NULL)
            continue;

        if (t->RegisterTests == NULL) {
            printf("Warning: threading module %s has no unittest "
                   "registration function.\n", t->name);
        } else {
            t->RegisterTests();
        }
    }
#endif /* UNITTESTS */
}

