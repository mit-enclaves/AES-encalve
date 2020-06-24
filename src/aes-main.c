#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PAGE_SIZE 4096

// security monitor API
#include <api.h>

#include "aes-enclave-api.h"

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct run_enclave*)

int call_enclave(const char *enclave_bin_name, aes_enclave_params_t *params) {
    int fd = 0;
    struct arg_start_enclave val;
    fd = open("/dev/security_monitor", O_RDWR);
    fprintf(stderr, "file descriptor fd(%d)", fd);;
    if (fd < 0) {
        fprintf(stderr, "File open error: %s\n", strerror(errno));
        return -2;
    }
    FILE *ptr;
    ptr = fopen(enclave_bin_name,"rb");
    struct stat statbuf;
    stat(enclave_bin_name, &statbuf);
    off_t sizefile = statbuf.st_size;
    fprintf(stderr, "Size enclave.bin (%ld)\n", sizefile);
    char* enclave = memalign(1<<12,sizefile);
    size_t sizecopied = fread(enclave, sizefile, 1, ptr);
    fprintf(stderr, "Size copied: %ld", sizecopied);
    fclose(ptr);

    /* Allocate memory to share with the enclave. Need to find a proper place for that */
#define begin_shared 0xF000000
#define shared_size ((sizeof(aes_enclave_params_t) + PAGE_SIZE - 1) & ~PAGE_SIZE)
    char* shared_enclave = (char *)mmap((void *)begin_shared, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // 
    if (shared_enclave == MAP_FAILED) {
        perror("Shared memory not allocated in a correct place, last errno: ");
        return -2;
    }
    fprintf(stderr, "Address for the shared enclave %08lx size %ld", (long)shared_enclave, shared_size);

    memset(shared_enclave, 0, shared_size);
    memcpy(shared_enclave, params, sizeof(*params));

    val.enclave_start = (long)enclave;
    val.enclave_end = (long)(enclave + sizefile - 4096); // last page contains nonces and measurement
    int ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);

    if (ret == 0) {
	memcpy(params, shared_enclave, sizeof(*params));
    } else {
        fprintf(stderr, "IOCTL error: %s\n", strerror(errno));
    }

    memset(shared_enclave, 0, shared_size);
    munmap(shared_enclave, shared_size);
    close(fd);
    return ret;
}


int main(int argc, char *const *argv)
{
    int opt;
    int encrypt = 0;
    int decrypt = 0;

    while ((opt = getopt(argc, argv, "def")) != -1) {
	switch (opt) {
	case 'd':
	    decrypt = 1;
	    break;
	case 'e':
	    encrypt = 1;
	    break;
	default: /* '?' */
	    fprintf(stderr, "Usage: %s [-d] [-e] file\n",
		    argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
    fprintf(stderr, "optind %d argc %d\n", optind, argc);
    const char *infile = argv[optind];
    const char *outfile = argv[optind + 1];
    fprintf(stderr, "encrypt %d decrypt %d %s %s\n", encrypt, decrypt, infile, outfile);

    struct stat statbuf = {0};
    int stat_result = lstat(infile, &statbuf);
    if (stat_result < 0) {
	fprintf(stderr, "Input file %s does not exist (%s)\n", infile, strerror(errno));
	return -2;
    }

    aes_enclave_params_t *params = calloc(1, offsetof(aes_enclave_params_t, message) + statbuf.st_size);
    fprintf(stderr, "params %p size %ld\n", params, offsetof(aes_enclave_params_t, message) + statbuf.st_size);
    params->message_len = statbuf.st_size;

    int infd = open(infile, O_RDONLY);
    if (infd < 0) {
	fprintf(stderr, "Error opening input file %s (%s)\n", infile, strerror(errno));
	return -2;
    }

    if (encrypt) {
	params->opcode = OPCODE_ENCRYPT;
	int offset = 0;
	int bytes_to_read = statbuf.st_size;
	while (bytes_to_read) {
	    int bytes_read = read(infd, params->message + offset, bytes_to_read);
	    if (bytes_read < 0) {
		fprintf(stderr, "Error reading %s at offset %d: %s\n", infile, offset, strerror(errno));
		return -2;
	    }
	    offset += bytes_read;
	    bytes_to_read -= bytes_read;
	}
    } else if (decrypt) {
	int offset = 0;
	int bytes_to_read = statbuf.st_size;
	char *buf = (char *)params;
	while (bytes_to_read) {
	    int bytes_read = read(infd, buf + offset, bytes_to_read);
	    if (bytes_read < 0) {
		fprintf(stderr, "Error reading %s at offset %d: %s\n", infile, offset, strerror(errno));
		return -2;
	    }
	    offset += bytes_read;
	    bytes_to_read -= bytes_read;
	}
	params->opcode = OPCODE_DECRYPT;
	params->message_len = statbuf.st_size - offsetof(aes_enclave_params_t, message);
    }

    close(infd);

    int result = 0;
    if (encrypt || decrypt) {
	fprintf(stderr, "calling enclave\n");
	result = call_enclave("/ssith/aes-enclave.bin", params);
	fprintf(stderr, "call_enclave => %d params->result %d\n", result, params->result);
    }
    int outfd = open(outfile, O_RDWR|O_CREAT|O_TRUNC, 0664);
    if (outfd < 0) {
	fprintf(stderr, "Error opening output file %s (%s)\n", outfile, strerror(errno));
	return -2;
    }

    if (encrypt) {
	memcpy((char *)&params->magic, "AESE", 4);
	int offset = 0;
	int bytes_to_write = statbuf.st_size + offsetof(aes_enclave_params_t, message);
	char *buf = (char *)params;
	while (bytes_to_write) {
	    int bytes_write = write(outfd, buf + offset, bytes_to_write);
	    if (bytes_write < 0) {
		fprintf(stderr, "Error writing %s at offset %d: %s\n", infile, offset, strerror(errno));
		return -2;
	    }
	    offset += bytes_write;
	    bytes_to_write -= bytes_write;
	}
    } else if (decrypt) {
	params->opcode = OPCODE_DECRYPT;
	int offset = 0;
	int bytes_to_write = statbuf.st_size - offsetof(aes_enclave_params_t, message);
	char *buf = (char *)params->message;
	while (bytes_to_write) {
	    int bytes_write = write(outfd, buf + offset, bytes_to_write);
	    if (bytes_write < 0) {
		fprintf(stderr, "Error writing %s at offset %d: %s\n", infile, offset, strerror(errno));
		return -2;
	    }
	    offset += bytes_write;
	    bytes_to_write -= bytes_write;
	}
	params->message_len = statbuf.st_size - offsetof(aes_enclave_params_t, message);
    }
    close(outfd);

    if (params)
	free(params);


    return result;
}
