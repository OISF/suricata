#include "suricata-common.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static int runOneFile(const char *fname)
{
    // opens the file, get its size, and reads it into a buffer
    uint8_t *data;
    size_t size;
    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        return 2;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return 2;
    }
    size = ftell(fp);
    if (size == (size_t) -1) {
        fclose(fp);
        return 2;
    }
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        fclose(fp);
        return 2;
    }
    data = malloc(size);
    if (data == NULL) {
        fclose(fp);
        return 2;
    }
    if (fread(data, size, 1, fp) != 1) {
        fclose(fp);
        free(data);
        return 2;
    }

    //launch fuzzer
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    DIR *d;
    struct dirent *dir;
    int r;

    if (argc != 2) {
        return 1;
    }
#ifdef AFLFUZZ_PERSISTANT_MODE
    while (__AFL_LOOP(1000)) {
#endif /* AFLFUZZ_PERSISTANT_MODE */

        d = opendir(argv[1]);
        if (d == NULL) {
            // run one file
            r = runOneFile(argv[1]);
            if (r != 0) {
                return r;
            }
        } else {
            // run every file in one directory
            if (chdir(argv[1]) != 0) {
                closedir(d);
                printf("Invalid directory\n");
                return 2;
            }
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type != DT_REG) {
                    continue;
                }
                r = runOneFile(dir->d_name);
                if (r != 0) {
                    return r;
                }
            }
            closedir(d);
        }
#ifdef AFLFUZZ_PERSISTANT_MODE
    }
#endif /* AFLFUZZ_PERSISTANT_MODE */

    return 0;
}
