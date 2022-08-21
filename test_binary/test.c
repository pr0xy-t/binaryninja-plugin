#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

int main()
{
	int fd = open("./a.out", O_RDONLY);
	off_t t = lseek(fd, 0, SEEK_END);
	t = lseek(1, 0, SEEK_END);
	void *t2 = mmap(NULL, 0x1000, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
}
