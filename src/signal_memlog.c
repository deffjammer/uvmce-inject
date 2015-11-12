#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/file.h>

#define COMMAND_LINE_SIZE 512


int main (int argc, char** argv) {                                     
	FILE *fp;
        int status;
        char cmd_out[COMMAND_LINE_SIZE];
	char *run_string = NULL;

	run_string =  "ps -C memlogd | grep -v 'PID' | awk -F \" \" '{print $1}' ";

        /* Open the command for reading. */
        fp = popen(run_string, "r");
        if (fp == NULL) {
                printf("Failed to run: %s\n", run_string );
                return -1;
        }

        /* Read the output a line at a time - output it. */
        while (fgets(cmd_out, sizeof(cmd_out)-1, fp) != NULL) {
                printf("%s", cmd_out);
        }

	

        /* close */
        pclose(fp);
}

	
