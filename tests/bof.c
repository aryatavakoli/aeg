/* 
 *
 * Compile with :
 *   $ gcc bof.c -o bof -m32 -static 
 *
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char buf[4];
    void (*f)();
} Some_struct;

void call_me(){
    printf("Call me\n");
    exit(0);
}

void nothing(){
}

int vuln(char *src)
{
    Some_struct st;
    st.f = nothing;
    strcpy(st.buf, src); // buffer overflow
    st.f();
    return 0;
}

int main(int argc, char* argv[]){

    if(argc != 2){
        printf("Usage ./bof input");
    }

    if(argv[1][0] == 'A' ){ // the input has to start with 'A'
        vuln(argv[1]);
        return 0;
    }
}