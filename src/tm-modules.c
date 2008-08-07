/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "tm-modules.h"

TmModule tmm_modules[TMM_SIZE];

void TmModuleDebugList(void) {
    TmModule *t;
    u_int16_t i;

    printf("TmModuleDebugList: start\n");
    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        printf("TmModuleDebugList: %s:%p\n", t->name, t->Func);
    }
    printf("TmModuleDebugList: end\n");
}

TmModule *TmModuleGetByName(char *name) {
    TmModule *t;
    u_int16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (strcmp(t->name, name) == 0)
            return t;
    }

    return NULL;
}

void TmModuleRegisterTests(void) {
    TmModule *t;
    u_int16_t i;

    for (i = 0; i < TMM_SIZE; i++) {
        t = &tmm_modules[i];

        if (t->RegisterTests == NULL) {
            printf("Warning: threading module %s has no unittest "
                   "registration function.\n", t->name);
        } else {
            t->RegisterTests();
        }
    }
}

