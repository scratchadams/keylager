#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

static ssize_t (*original_read)(int fd, void *buf, size_t count) = NULL;

char *remove_txt(char *txt, char *o_bracket, char *c_bracket) {
	char *o_remove, *c_remove;
	char *new_string = malloc(strlen(txt));
	int o_pos, c_pos;
	int j = 0;

	if((o_remove = strstr(txt, o_bracket)) == NULL) {
		return txt;
	}
	if((c_remove = strstr(txt, c_bracket)) == NULL) {
		return txt;
	}
	
	o_pos = o_remove - txt;
	c_pos = c_remove - txt;

	for(int i=0;i<strlen(txt)-1;i++) {
		if(i >= o_pos && i <= c_pos+strlen(c_bracket)) {
			continue;
		}
		new_string[j] = txt[i];
		j++;
	}

	//printf("test: %s\n", new_string);
	return new_string;
	
}

ssize_t read(int fd, void *buf, size_t count) {
	//char buf[1000];
	//int fd = open("test.read", O_RDWR);
	char *n_buf;
	ssize_t o_read = 0;

	//printf("1st buf: %x\n", &buf);

	if(original_read == NULL) {
		original_read = dlsym(RTLD_NEXT, "read");

		if(original_read == NULL) {
			fprintf(stderr, "Error in dlsym: %s\n", dlerror());
		}
	}
	
	if((o_read = original_read(fd, buf, count)) != -1) {
		n_buf = malloc(strlen(buf));
		n_buf = remove_txt(buf, "<remove>", "</remove>");
		n_buf[strlen(n_buf)] = '\n';
		memcpy(buf, n_buf, strlen(buf));
		//original_read(3, buf, count);		
		//printf("o_read: %li\n", o_read);
		//printf("buf: %x\n", &buf);
		//return o_read;
	}
	
	return o_read;
}
