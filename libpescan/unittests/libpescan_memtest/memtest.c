#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libpescan.h"

#define CHUNK_SIZE 1024

uint8_t *getFileBytes(const char *filename, uint32_t *len) {

    uint8_t *temp, *buf = NULL;
    uint32_t numBytes = 0, size = CHUNK_SIZE;
    int c;
    FILE *fptr = fopen(filename, "rb");
    if (fptr != NULL) {

	buf = (uint8_t *) malloc(CHUNK_SIZE + 1);
	while ((c = fgetc(fptr)) != EOF) {

	    /* Reallocate */
	    if (numBytes == size) {
		size += CHUNK_SIZE;
		temp = buf;
		buf = (uint8_t *) malloc(size + 1);
		memcpy(buf, temp, numBytes);
		free(temp);
	    }

	    /* Set char */
	    buf[numBytes] = c;

	    numBytes++;
	}
	buf[numBytes] = 0;

	/* Pass back the length into the pointer */
	if (len != NULL) {
	    *len = numBytes;
	}

	fclose(fptr);
    }

    return buf;
}

int scanFile(char *buf, uint32_t len, peattrib_t *peat, int debug) {

    int status;

    status = pescan(peat, (unsigned char *) buf, len, debug);
    if (debug) {
	printf("Status: %d\n", status);
    }

    return status;
}

int boundsCheckTest(uint8_t *exe, uint32_t len) {

    int ret;
    peattrib_t peat;
    char *cpy;
    uint32_t idx;
    uint32_t max_idx = 5000;

    if (max_idx > len) {
	printf("Max value is out of range (%d > %d)\n", max_idx, len);
    }

    /*Now test for buffer overflow */
    for (idx = 0; idx < max_idx; idx++) {

	cpy = (char *) malloc(idx);
	memcpy(cpy, exe, idx);
	ret = scanFile(cpy, idx, &peat, 0);

	free(cpy);
    }

    return ret;
}

int main(int argc, char *argv[]) {

    uint32_t len;
    uint8_t *exe = getFileBytes("data/CCleaner.exe", &len);
    if (exe != NULL) {

	/* Test bounds checking (w/Valgrind compilation) */
	boundsCheckTest(exe, len);

	free(exe);
	printf("Test successfully completed\n\n");
    }
    else {
	printf("Could not open file\n");
    }

    return 0;
}
