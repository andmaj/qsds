#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "qsds.h"
#include "mpa.h"

int compress(void *addr, int fd, off_t length);

int main(int argc, char *argv[])
{
	struct stat info;
	int fd;
	void *addr;

	if(argc!=2)
	{
		fprintf(stderr, "Usage: qsds <filename>");
		return EXIT_FAILURE;
	}

	fd = open(argv[1], O_RDONLY);
	if(fd < 0)
	{
		perror("Could not open file");
		return EXIT_FAILURE;
	}

	if (fstat(fd, &info) != 0)
	{
		perror("Could not stat the file");
		return EXIT_FAILURE;
	}

	addr = mmap(NULL, info.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
	{
		close(fd);
		perror("Could not mmap the file");
		return EXIT_FAILURE;
	}

	return compress(addr, fd, info.st_size);
}

int compress(void *addr, int fd, off_t length)
{
	qsds_input_prop input_prop;
	qsds ds;

	if(qsds_input_analyze(addr, length, &input_prop))
	{
		fprintf(stderr, "Error while analyzing the input");
		return EXIT_FAILURE;
	}

#ifdef DEBUG
	printf("Number of ones = %" PRIu64 "\n", input_prop.num_ones);
	printf("Bit index of the last 1 bit = %" PRIu64 "\n", input_prop.idx_last_one);
#endif

	if(qsds_compress(&ds, addr, length, &input_prop))
	{
		fprintf(stderr, "Error while compressing the input");
		return EXIT_FAILURE;
	}

	qsds_free(&ds);
	munmap(addr, length);
	close(fd);
	return EXIT_SUCCESS;
}
