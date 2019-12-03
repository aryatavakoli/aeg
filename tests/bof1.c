#include <stdio.h>
#include <stdlib.h>
#include "pwnable_harness.h"

void win(void) {
	char flag[64];
	
	FILE* fp = fopen("flag.txt", "r");
	if(!fp) {
		puts("error, contact admin");
		exit(0);
	}
	
	fgets(flag, sizeof(flag), fp);
	fclose(fp);
	puts(flag);
}

void handle_connection(int sock) {
	int admin = 0;
	char buf[32];
	
	scanf("%s", buf);
	
	if(admin) {
		win();
	}
	else {
		puts("nope!");
	}
}
