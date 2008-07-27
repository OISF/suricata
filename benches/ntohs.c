#include <stdlib.h>
#include <stdio.h>

int b=0;
int c=0;
char flag = 0;

#define PASS_A(a) flag & 0x01 ? c : (flag |= 0x01, c = ntohs(a))


int dosomething(int a) {
    return a;
}

int main() {
    int i = 0;
    int a = 1234;

    //for (i = 0; i < 100000000L; i++) {
    for (i = 0; i < 10; i++) {
        printf("PRE : a %d b %d c %d, flag %s\n", a,b,c, flag & 0x01 ? "SET":"NOT SET");

        a = dosomething(PASS_A(a));
        
        printf("POST: a %d b %d c %d, flag %s\n", a,b,c, flag & 0x01 ? "SET":"NOT SET");

//        a = ntohs(a);
    }

    exit(0);
}

