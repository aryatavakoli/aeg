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

void lose(void) {
	puts("you suck!\n");
	fflush(stdout);
	exit(0);
}

void handle_connection(int sock) {
	void (*fp)(); 
	char bof[64];
	
	fp = &lose;
	
	scanf("%s",bof);
	fp();
}


int main(int argc, char** argv) {
	/* Defaults: Run on port 9002 for 30 seconds as user "ctf_bof3" in a chroot */
	server_options opts = {
		.user = "ctf_bof3",
		.chrooted = true,
		.port = 9002,
		.time_limit_seconds = 30
	};
	
	return server_main(argc, argv, opts, &handle_connection);
}
