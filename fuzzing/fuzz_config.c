// Copyright (c) 2018 Code Intelligence. All rights reserved.

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "suricata-common.h"

#include "conf-yaml-loader.h"
#include "detect-parse.h"
#include "detect-engine-content-inspection.h"
#include "pkt-var.h"
#include "flow-util.h"
#include "stream-tcp-reassemble.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    ConfCreateContextBackup();
    ConfInit();
    return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    int buffer_size = 16;
    char fuzz_buffer[size+buffer_size];
    char buffer[] = "%YAML 1.1\n---\n";
    
    memset(fuzz_buffer,0,size);
    memcpy(fuzz_buffer+(16*(sizeof(char))),data,size);  

    ConfYamlLoadString(fuzz_buffer, sizeof(fuzz_buffer));

    return 0;
}
