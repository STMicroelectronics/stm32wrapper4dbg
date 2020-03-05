// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause

/*
 * Copyright (c) 2017-2020, STMicroelectronics - All Rights Reserved
 */

#include <asm/byteorder.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Magic = 'S' 'T' 'M' 0x32 */
#define HEADER_MAGIC		__be32_to_cpu(0x53544D32)
#define VER_MAJOR		2
#define VER_MINOR		1
#define VER_VARIANT		0
#define HEADER_VERSION_V1	0x1
#define TF_BINARY_TYPE		0x10

/* Default option : bit0 => no signature */
#define HEADER_DEFAULT_OPTION	(__cpu_to_le32(0x00000001))

#define ARM_THUMB_ADDRESS(a)	((a) | 1)
#define ARM_THUMB_INSN(a)	((a) & ~1)
#define ALIGN(x, a)		(((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)	((x) & ~((a) - 1))
#define WRAPPER_ALIGNMENT	64UL

static uint8_t stm32_wrapper[] = {
#include "wrapper_stm32mp15x.inc"
};

struct stm32_header {
	uint32_t magic_number;
	uint8_t image_signature[64];
	uint32_t image_checksum;
	uint8_t  header_version[4];
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t reserved1;
	uint32_t load_address;
	uint32_t reserved2;
	uint32_t version_number;
	uint32_t option_flags;
	uint32_t ecdsa_algorithm;
	uint8_t ecdsa_public_key[64];
	uint8_t padding[83];
	uint8_t binary_type;
};

static void stm32image_default_header(struct stm32_header *ptr)
{
	if (!ptr) {
		return;
	}

	ptr->magic_number = HEADER_MAGIC;
	ptr->option_flags = HEADER_DEFAULT_OPTION;
	ptr->ecdsa_algorithm = __cpu_to_le32(1);
	ptr->version_number = __cpu_to_le32(0);
	ptr->binary_type = TF_BINARY_TYPE;
}

static uint32_t stm32image_checksum(void *start, uint32_t len)
{
	uint32_t csum = 0;
	uint32_t hdr_len = sizeof(struct stm32_header);
	uint8_t *p;

	if (len < hdr_len) {
		return 0;
	}

	p = (unsigned char *)start + hdr_len;
	len -= hdr_len;

	while (len > 0) {
		csum += *p;
		p++;
		len--;
	}

	return csum;
}

static int stm32image_check_hdr(void *ptr, uint32_t file_length)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;
	uint32_t img_length = file_length - sizeof(struct stm32_header);

	if (file_length <= sizeof(struct stm32_header)) {
		fprintf(stderr, "File too small\n");
		return -1;
	}

	if (stm32hdr->magic_number != HEADER_MAGIC) {
		fprintf(stderr, "Wrong header magic\n");
		return -1;
	}

	if (__le32_to_cpu(stm32hdr->image_length) > img_length) {
		fprintf(stderr, "Wrong image length\n");
		return -1;
	}

	/* There could be padding at the end of input file */
	img_length = __le32_to_cpu(stm32hdr->image_length);
	file_length = sizeof(struct stm32_header) + img_length;

	if (__le32_to_cpu(stm32hdr->image_checksum) !=
	    stm32image_checksum(ptr, file_length)) {
		fprintf(stderr, "Wrong image checksum\n");
		return -1;
	}

	if (stm32hdr->reserved1 || stm32hdr->reserved2) {
		fprintf(stderr, "Wrong image, reserved fields not zero\n");
		return -1;
	}

	for (int i = 0; i < sizeof(stm32hdr->padding); i++) {
		if (stm32hdr->padding[i]) {
			fprintf(stderr, "Wrong image, padding not zero\n");
			return -1;
		}
	}

	if ((__le32_to_cpu(stm32hdr->image_entry_point) <
	     __le32_to_cpu(stm32hdr->load_address)) ||
	    (__le32_to_cpu(stm32hdr->image_entry_point) >=
	     __le32_to_cpu(stm32hdr->load_address) + img_length)) {
		fprintf(stderr, "Wrong image entry point\n");
		return -1;
	}

	return 0;
}

static int stm32image_check_wrapper(void *ptr)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;
	uint32_t file_length, loadaddr, entry, pos;

	file_length = sizeof(struct stm32_header) + __le32_to_cpu(stm32hdr->image_length);
	loadaddr = __le32_to_cpu(stm32hdr->load_address);
	entry = ARM_THUMB_INSN(__le32_to_cpu(stm32hdr->image_entry_point));

	pos = sizeof(struct stm32_header) + entry - loadaddr;
	if (pos + sizeof(stm32_wrapper) + sizeof(uint32_t) > file_length)
		return 0;

	if (memcmp(((char *)ptr) + pos, stm32_wrapper, sizeof(stm32_wrapper)))
		return 0;

	return -1;
}

static void stm32image_print_header(const void *ptr)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;

	printf("Image Type   : ST Microelectronics STM32 V%d.%d\n",
	       stm32hdr->header_version[VER_MAJOR],
	       stm32hdr->header_version[VER_MINOR]);
	printf("Image Size   : %lu bytes\n",
	       (unsigned long)__le32_to_cpu(stm32hdr->image_length));
	printf("Image Load   : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->load_address));
	printf("Entry Point  : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->image_entry_point));
	printf("Checksum     : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->image_checksum));
	printf("Option       : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->option_flags));
	printf("Version	     : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->version_number));
}

static void stm32image_set_header(void *ptr, uint32_t file_size, int ifd,
				  uint32_t loadaddr, uint32_t ep, uint32_t ver,
				  uint32_t major, uint32_t minor, uint8_t type)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;

	stm32image_default_header(stm32hdr);

	stm32hdr->header_version[VER_MAJOR] = major;
	stm32hdr->header_version[VER_MINOR] = minor;
	stm32hdr->load_address = __cpu_to_le32(loadaddr);
	stm32hdr->image_entry_point = __cpu_to_le32(ep);
	stm32hdr->image_length = __cpu_to_le32(file_size -
					     sizeof(struct stm32_header));
	stm32hdr->image_checksum =
		__cpu_to_le32(stm32image_checksum(ptr, file_size));
	stm32hdr->version_number = __cpu_to_le32(ver);
	stm32hdr->binary_type = type;
}

static int stm32image_create_header_file(char *srcname, char *destname,
					 int wrapper_before, int force)
{
	int src_fd, dest_fd;
	struct stat sbuf;
	unsigned char *ptr;
	struct stm32_header stm32image_header;
	struct stm32_header *stm32hdr;
	unsigned char *src_data;
	size_t src_size, dest_size;
	uint32_t src_length, jmp_add, padding, wrp_loadaddr, wrp_size;
	uint32_t new_loadaddr, new_entry = 0;
	uint32_t loadaddr, entry, version, major, minor, option;
	uint8_t type;

	dest_fd = open(destname, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0666);
	if (dest_fd == -1) {
		fprintf(stderr, "Can't open %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	src_fd = open(srcname, O_RDONLY);
	if (src_fd == -1) {
		fprintf(stderr, "Can't open %s: %s\n", srcname,
			strerror(errno));
		return -1;
	}

	if (fstat(src_fd, &sbuf) < 0) {
		return -1;
	}

	src_size = sbuf.st_size;
	if ((sbuf.st_mode & S_IFBLK) && (ioctl(src_fd, BLKGETSIZE64, &src_size) < 0)) {
		fprintf(stderr, "Can't read size of %s\n", srcname);
		return -1;
	}

	ptr = mmap(NULL, src_size, PROT_READ, MAP_SHARED, src_fd, 0);
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "Can't read %s\n", srcname);
		return -1;
	}

	if (stm32image_check_hdr(ptr, src_size) < 0) {
		fprintf(stderr, "Not a valid image file %s\n", srcname);
		return -1;
	}

	stm32hdr = (struct stm32_header *)ptr;
	src_data = ptr + sizeof(struct stm32_header);
	src_length = src_size - sizeof(struct stm32_header);

	if (__le32_to_cpu(stm32hdr->image_length) < src_length) {
                fprintf(stderr, "Strip extra padding from input file\n");
		src_length = __le32_to_cpu(stm32hdr->image_length);
		src_size = sizeof(struct stm32_header) + src_length;
	}

	if (force == 0 && stm32image_check_wrapper(ptr) < 0) {
		fprintf(stderr,
			"Wrapper already present in image file %s\n"
			"Use flag \"-f\" to force re-adding the wrapper\n",
			srcname);
		return -1;
	}

	major = stm32hdr->header_version[VER_MAJOR];
	minor = stm32hdr->header_version[VER_MINOR];
	entry = __le32_to_cpu(stm32hdr->image_entry_point);
	loadaddr = __le32_to_cpu(stm32hdr->load_address);
	version = __le32_to_cpu(stm32hdr->version_number);
	option = __le32_to_cpu(stm32hdr->option_flags);
	type = stm32hdr->binary_type;

	memset(&stm32image_header, 0, sizeof(struct stm32_header));

	if (write(dest_fd, &stm32image_header, sizeof(struct stm32_header)) !=
	    sizeof(struct stm32_header)) {
		fprintf(stderr, "Write error %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	wrp_size = sizeof(stm32_wrapper) + sizeof(jmp_add);
	if (wrapper_before == 1) {
		wrp_loadaddr = ALIGN_DOWN(loadaddr - wrp_size,
					  WRAPPER_ALIGNMENT);
		padding = loadaddr - (wrp_loadaddr + wrp_size);
		new_loadaddr = wrp_loadaddr;
	} else {
		wrp_loadaddr = ALIGN(loadaddr + src_length, WRAPPER_ALIGNMENT);
		padding = wrp_loadaddr - (loadaddr + src_length);
		new_loadaddr = loadaddr;
	}

	new_entry = ARM_THUMB_ADDRESS(wrp_loadaddr);
	jmp_add = __cpu_to_le32(entry);

	if (wrapper_before == 1) {
		if (write(dest_fd, stm32_wrapper, sizeof(stm32_wrapper)) !=
		    sizeof(stm32_wrapper)) {
			fprintf(stderr, "Write error on %s: %s\n", destname,
				strerror(errno));
			return -1;
		}

		if (write(dest_fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			fprintf(stderr, "Write error %s: %s\n", destname,
				strerror(errno));
			return -1;
		}

		/* sizeof(stm32image_header) bigger than max padding */
		if (write(dest_fd, &stm32image_header, padding) != padding) {
			fprintf(stderr, "Write error %s: %s\n", destname,
				strerror(errno));
			return -1;
		}
	}

	if (write(dest_fd, src_data, src_length) != src_length) {
		fprintf(stderr, "Write error on %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	if (wrapper_before == 0) {
		/* sizeof(stm32image_header) bigger than max padding */
		if (write(dest_fd, &stm32image_header, padding) != padding) {
			fprintf(stderr, "Write error %s: %s\n", destname,
				strerror(errno));
			return -1;
		}

		if (write(dest_fd, stm32_wrapper, sizeof(stm32_wrapper)) !=
		    sizeof(stm32_wrapper)) {
			fprintf(stderr, "Write error on %s: %s\n", destname,
				strerror(errno));
			return -1;
		}

		if (write(dest_fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			fprintf(stderr, "Write error on %s: %s\n", destname,
				strerror(errno));
			return -1;
		}
	}

	munmap((void *)ptr, src_size);
	close(src_fd);

	dest_size = sizeof(struct stm32_header) + wrp_size + padding + src_length;

	ptr = mmap(0, dest_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   dest_fd, 0);

	if (ptr == MAP_FAILED) {
		fprintf(stderr, "Can't write %s\n", destname);
		return -1;
	}

	stm32image_set_header(ptr, dest_size, dest_fd, new_loadaddr, new_entry,
			      version, major, minor, type);

	stm32image_print_header(ptr);
	printf("Halt Address : 0x%08x\n", jmp_add);

	if ((option & 1) == 0)
		printf("\nATTENTION:\n\tSource file \"%s\" was \"signed\"!\n"
		       "\tYou would need to sign the destination file \"%s\"\n",
		       srcname, destname);

	munmap((void *)ptr, dest_size);
	close(dest_fd);
	return 0;
}

int main(int argc, char *argv[])
{
	int opt, err, wrapper_before = 0, force = 0;
	char *dest = NULL, *src = NULL;

	while ((opt = getopt(argc, argv, "bfs:d:")) != -1) {
		switch (opt) {
		case 'b':
			wrapper_before = 1;
			break;
		case 'f':
			force = 1;
			break;
		case 's':
			src = optarg;
			break;
		case 'd':
			dest = optarg;
			break;
		default:
			fprintf(stderr,
				"Usage: %s -s srcfile -d destfile [-b] [-f]\n"
				"  Add a debug wrapper to a stm32 image.\n"
				"  If \"-b\" is not specified, the wrapper would be placed\n"
				"  after the last byte of the image.\n"
				"\nOptions:\n"
				"  -s srcfile   input image in stm32 file format\n"
				"  -d destfile  output image in stm32 file format\n"
				"  -b           place the wrapper before the image\n"
				"  -f           force re-adding the wrapper\n",
				argv[0]);
			return -1;
		}
	}

	if (!src) {
		fprintf(stderr, "Missing -s option\n");
		return -1;
	}

	if (!dest) {
		fprintf(stderr, "Missing -d option\n");
		return -1;
	}

	err = stm32image_create_header_file(src, dest, wrapper_before, force);

	return err;
}
