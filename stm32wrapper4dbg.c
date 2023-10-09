// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause

/*
 * Copyright (c) 2017-2021, STMicroelectronics - All Rights Reserved
 */

#include <asm/byteorder.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VERSION			"3.1.0"

/* Magic = 'S' 'T' 'M' 0x32 */
#define HEADER_MAGIC		__be32_to_cpu(0x53544D32)
#define VER_MAJOR		2
#define VER_MINOR		1
#define VER_VARIANT		0
#define HEADER_VERSION_V1	0x1
#define HEADER_VERSION_V2	0x2
#define PADDING_HEADER_MAGIC	__be32_to_cpu(0x5354FFFF)
#define PADDING_HEADER_FLAG	(1 << 31)
#define PADDING_HEADER_LENGTH	0x180
#define BIN_TYPE_CM33_IMAGE	0x30

#define ARM_THUMB_ADDRESS(a)	((a) | 1)
#define ARM_THUMB_INSN(a)	((a) & ~1)
#define ALIGN(x, a)		(((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)	((x) & ~((a) - 1))
#define WRAPPER_ALIGNMENT	64UL

#define STM32MP13X_SYSRAM_START	0x2ffe0000
#define STM32MP13X_SYSRAM_END	0x30000000

static uint8_t stm32_mp1_ca7_wrapper[] = {
#include "wrapper_stm32mp15x.inc"
};

static uint8_t stm32_mp2_ca35_wrapper[] = {
#include "wrapper_stm32mp25x.inc"
};

static uint8_t stm32_mp2_cm33_wrapper[] = {
};

static uint8_t *stm32_wrapper;
static unsigned int stm32_wrapper_size;
static const char *stm32_wrapper_string;
static int stm32_wrapper_is_arm_thumb;

struct stm32_header {
	uint32_t magic_number;
	uint8_t image_signature[64];
	uint32_t image_checksum;
	uint8_t header_version[4];
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t reserved1;
	uint32_t load_address;
	uint32_t reserved2;
	uint32_t version_number;
	union {
		struct {
			uint32_t option_flags;
			uint32_t ecdsa_algorithm;
			uint8_t ecdsa_public_key[64];
			uint8_t padding[83];
			uint8_t binary_type;
			/* used to get header length */
			uint8_t _last[0];
		} v1;
		struct {
			uint32_t extension_flags;
			uint32_t extension_headers_length;
			uint32_t binary_type;
			uint8_t padding[16];
			/* input file can have other extensions */
			struct {
				uint32_t type;
				uint32_t length;
				uint8_t padding[376];
			} extension;
		} v2;
	};
};

enum bin_type {
	BTYPE_UNKNOWN,
	BTYPE_ARMV7A,
	BTYPE_ARMV8A_64,
	BTYPE_ARMV8M,
};

static uint32_t stm32image_header_length(struct stm32_header *ptr)
{
	switch (ptr->header_version[VER_MAJOR]) {
	case HEADER_VERSION_V1:
		return offsetof(struct stm32_header, v1._last);
	case HEADER_VERSION_V2:
		return offsetof(struct stm32_header, v2.extension) +
			__le32_to_cpu(ptr->v2.extension_headers_length);
	default:
		return 0;
	}
}

static uint32_t stm32image_checksum(struct stm32_header *start, uint32_t len,
				    uint32_t hdr_len)
{
	uint32_t csum = 0;
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

static int stm32image_check_hdr(struct stm32_header *stm32hdr,
				uint32_t file_length)
{
	uint32_t hdr_length, img_length;

	if (file_length <= offsetof(struct stm32_header, v1)) {
		fprintf(stderr, "File too small\n");
		return -1;
	}

	if (stm32hdr->magic_number != HEADER_MAGIC) {
		fprintf(stderr, "Wrong header magic\n");
		return -1;
	}

	hdr_length = stm32image_header_length(stm32hdr);
	if (hdr_length == 0) {
		fprintf(stderr, "Unknown header version\n");
		return -1;
	}

	if (file_length <= hdr_length) {
		fprintf(stderr, "File too small\n");
		return -1;
	}

	img_length = file_length - hdr_length;
	if (__le32_to_cpu(stm32hdr->image_length) > img_length) {
		fprintf(stderr, "Wrong image length\n");
		return -1;
	}

	/* There could be padding at the end of input file */
	img_length = __le32_to_cpu(stm32hdr->image_length);
	file_length = hdr_length + img_length;

	if (__le32_to_cpu(stm32hdr->image_checksum) !=
	    stm32image_checksum(stm32hdr, file_length, hdr_length)) {
		fprintf(stderr, "Wrong image checksum\n");
		return -1;
	}

	if (stm32hdr->reserved1 || stm32hdr->reserved2) {
		fprintf(stderr, "Wrong image, reserved fields not zero\n");
		return -1;
	}

	switch (stm32hdr->header_version[VER_MAJOR]) {
	case HEADER_VERSION_V1:
		for (int i = 0; i < sizeof(stm32hdr->v1.padding); i++) {
			if (stm32hdr->v1.padding[i]) {
				fprintf(stderr, "Wrong image, padding not zero\n");
				return -1;
			}
		}
		break;
	case HEADER_VERSION_V2:
		for (int i = 0; i < sizeof(stm32hdr->v2.padding); i++) {
			if (stm32hdr->v2.padding[i]) {
				fprintf(stderr, "Wrong image, padding not zero\n");
				return -1;
			}
		}
		break;
	default:
		return -1;
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

/* Use some heuristics to detect the binary type of the image */
static enum bin_type stm32image_get_bin_type(struct stm32_header *stm32hdr)
{
	uint32_t loadaddr;

	/* stm32mp15x */
	if (stm32hdr->header_version[VER_MAJOR] == HEADER_VERSION_V1)
		return BTYPE_ARMV7A;

	/* stm32mp13x */
	loadaddr = __le32_to_cpu(stm32hdr->load_address);
	if (loadaddr >= STM32MP13X_SYSRAM_START && loadaddr < STM32MP13X_SYSRAM_END)
		return BTYPE_ARMV7A;

	/* stm32mp25x CM33 */
	if (__le32_to_cpu(stm32hdr->v2.binary_type) == BIN_TYPE_CM33_IMAGE)
		return BTYPE_ARMV8M;

	/* stm32mp25x CA35 */
	return BTYPE_ARMV8A_64;
}

static int stm32image_set_wrapper(struct stm32_header *stm32hdr)
{
	switch (stm32image_get_bin_type(stm32hdr)) {
	case BTYPE_ARMV7A:
		stm32_wrapper = stm32_mp1_ca7_wrapper;
		stm32_wrapper_size = sizeof(stm32_mp1_ca7_wrapper);
		stm32_wrapper_string = "STM32MP1xx Cortex-A7";
		stm32_wrapper_is_arm_thumb = 1;
		break;
	case BTYPE_ARMV8A_64:
		stm32_wrapper = stm32_mp2_ca35_wrapper;
		stm32_wrapper_size = sizeof(stm32_mp2_ca35_wrapper);
		stm32_wrapper_string = "STM32MP2xx Cortex-A35";
		stm32_wrapper_is_arm_thumb = 0;
		break;
	case BTYPE_ARMV8M:
		stm32_wrapper = stm32_mp2_cm33_wrapper;
		stm32_wrapper_size = sizeof(stm32_mp2_cm33_wrapper);
		stm32_wrapper_string = "STM32MP2xx Cortex-M33";
		stm32_wrapper_is_arm_thumb = 1;
		fprintf(stderr, "Image for Cortex-M33 not supported yet\n");
		return -1;
	case BTYPE_UNKNOWN:
	default:
		fprintf(stderr, "Cannot detect image type\n");
		return -1;
	}

	return 0;
}

static int stm32image_check_wrapper(struct stm32_header *stm32hdr)
{
	uint32_t file_length, loadaddr, entry, pos, hdr_length;

	hdr_length = stm32image_header_length(stm32hdr);
	file_length = hdr_length + __le32_to_cpu(stm32hdr->image_length);
	loadaddr = __le32_to_cpu(stm32hdr->load_address);
	entry = ARM_THUMB_INSN(__le32_to_cpu(stm32hdr->image_entry_point));

	pos = hdr_length + entry - loadaddr;
	if (pos + stm32_wrapper_size + sizeof(uint32_t) > file_length)
		return 0;

	if (memcmp(((char *)stm32hdr) + pos, stm32_wrapper, stm32_wrapper_size))
		return 0;

	return -1;
}

static void stm32image_print_header(const void *ptr)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;

	printf("Image Type   : ST Microelectronics STM32 V%d.%d\n",
	       stm32hdr->header_version[VER_MAJOR],
	       stm32hdr->header_version[VER_MINOR]);
	printf("Image Target : %s\n", stm32_wrapper_string);
	printf("Image Size   : %lu bytes\n",
	       (unsigned long)__le32_to_cpu(stm32hdr->image_length));
	printf("Image Load   : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->load_address));
	printf("Entry Point  : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->image_entry_point));
	printf("Checksum     : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->image_checksum));

	switch (stm32hdr->header_version[VER_MAJOR]) {
	case HEADER_VERSION_V1:
		printf("Option       : 0x%08x\n",
		       __le32_to_cpu(stm32hdr->v1.option_flags));
		break;

	case HEADER_VERSION_V2:
		printf("Extension    : 0x%08x\n",
		       __le32_to_cpu(stm32hdr->v2.extension_flags));
		break;

	default:
		printf("Incorrect header version\n");
	}

	printf("Version	     : 0x%08x\n",
	       __le32_to_cpu(stm32hdr->version_number));
}

static int stm32image_init_header(struct stm32_header *dest_hdr,
				  struct stm32_header *src_hdr)
{
	memset(dest_hdr, 0, sizeof(struct stm32_header));

	dest_hdr->magic_number = HEADER_MAGIC;
	dest_hdr->version_number = src_hdr->version_number;
	dest_hdr->header_version[VER_MAJOR] = src_hdr->header_version[VER_MAJOR];
	dest_hdr->header_version[VER_MINOR] = src_hdr->header_version[VER_MINOR];
	switch (src_hdr->header_version[VER_MAJOR]) {
	case HEADER_VERSION_V1:
		/* Default option for header v1 : bit0 => no signature */
		dest_hdr->v1.option_flags = __cpu_to_le32(0x00000001);
		dest_hdr->v1.ecdsa_algorithm = __cpu_to_le32(1);
		dest_hdr->v1.binary_type = src_hdr->v1.binary_type;
		break;
	case HEADER_VERSION_V2:
		dest_hdr->v2.binary_type = src_hdr->v2.binary_type;
		dest_hdr->v2.extension_flags =
			__cpu_to_le32(PADDING_HEADER_FLAG);
		dest_hdr->v2.extension_headers_length =
			__cpu_to_le32(PADDING_HEADER_LENGTH);
		dest_hdr->v2.extension.type = PADDING_HEADER_MAGIC;
		dest_hdr->v2.extension.length =
			__cpu_to_le32(PADDING_HEADER_LENGTH);
		break;
	default:
		return -1;
	}
	return 0;
}

static int stm32image_update_header(void *ptr, uint32_t file_size,
				    uint32_t loadaddr, uint32_t ep)
{
	struct stm32_header *stm32hdr = (struct stm32_header *)ptr;
	uint32_t hdr_length;

	hdr_length = stm32image_header_length(stm32hdr);

	stm32hdr->load_address = __cpu_to_le32(loadaddr);
	stm32hdr->image_entry_point = __cpu_to_le32(ep);
	stm32hdr->image_length = __cpu_to_le32(file_size - hdr_length);
	stm32hdr->image_checksum =
		__cpu_to_le32(stm32image_checksum(stm32hdr, file_size, hdr_length));
	return 0;
}

static int stm32image_create_header_file(char *srcname, char *destname,
					 int wrapper_before, int force)
{
	int src_fd, dest_fd;
	struct stat sbuf;
	unsigned char *ptr;
	struct stm32_header stm32image_header;
	struct stm32_header *src_hdr;
	uint32_t src_hdr_length, dest_hdr_length;
	unsigned char *src_data;
	size_t src_size, dest_size;
	uint32_t src_data_length, jmp_add, padding, wrp_loadaddr, wrp_size;
	uint32_t new_loadaddr, new_entry = 0;
	uint32_t loadaddr, entry, option;
	bool is_signed, is_encrypted;
	unsigned char padding_zeros[WRAPPER_ALIGNMENT];

	memset(padding_zeros, 0, sizeof(padding_zeros));

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
	src_hdr = (struct stm32_header *)ptr;

	if (stm32image_check_hdr(src_hdr, src_size) < 0) {
		fprintf(stderr, "Not a valid image file %s\n", srcname);
		return -1;
	}

	src_hdr_length = stm32image_header_length(src_hdr);
	src_data = ptr + src_hdr_length;
	src_data_length = src_size - src_hdr_length;

	if (stm32image_set_wrapper(src_hdr) < 0)
		return -1;

	if (__le32_to_cpu(src_hdr->image_length) < src_data_length) {
                fprintf(stderr, "Strip extra padding from input file\n");
		src_data_length = __le32_to_cpu(src_hdr->image_length);
		src_size = src_hdr_length + src_data_length;
	}

	if (force == 0 && stm32image_check_wrapper(src_hdr) < 0) {
		fprintf(stderr,
			"Wrapper already present in image file %s\n"
			"Use flag \"-f\" to force re-adding the wrapper\n",
			srcname);
		return -1;
	}

	entry = __le32_to_cpu(src_hdr->image_entry_point);
	loadaddr = __le32_to_cpu(src_hdr->load_address);

	switch (src_hdr->header_version[VER_MAJOR]) {
	case HEADER_VERSION_V1:
		option = __le32_to_cpu(src_hdr->v1.option_flags);
		is_signed = (option & 1) == 0;
		is_encrypted = false;
		break;
	case HEADER_VERSION_V2:
		option = __le32_to_cpu(src_hdr->v2.extension_flags);
		is_signed = (option & 1) != 0;
		is_encrypted = (option & 2) != 0;
		break;
	default:
		return -1;
	}

	if (is_encrypted) {
		fprintf(stderr,
			"Image %s is encrypted. Unable to extract the content.\n",
			srcname);
		return -1;
	}

	dest_fd = open(destname, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0666);
	if (dest_fd == -1) {
		fprintf(stderr, "Can't open %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	if (stm32image_init_header(&stm32image_header, src_hdr) < 0)
		return -1;

	dest_hdr_length = stm32image_header_length(&stm32image_header);

	if (write(dest_fd, &stm32image_header, dest_hdr_length) != dest_hdr_length) {
		fprintf(stderr, "Write error %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	wrp_size = stm32_wrapper_size + sizeof(jmp_add);
	if (wrapper_before == 1) {
		wrp_loadaddr = ALIGN_DOWN(loadaddr - wrp_size,
					  WRAPPER_ALIGNMENT);
		padding = loadaddr - (wrp_loadaddr + wrp_size);
		new_loadaddr = wrp_loadaddr;
	} else {
		wrp_loadaddr = ALIGN(loadaddr + src_data_length, WRAPPER_ALIGNMENT);
		padding = wrp_loadaddr - (loadaddr + src_data_length);
		new_loadaddr = loadaddr;
	}

	new_entry = (stm32_wrapper_is_arm_thumb) ? ARM_THUMB_ADDRESS(wrp_loadaddr) : wrp_loadaddr;

	jmp_add = __cpu_to_le32(entry);

	if (wrapper_before == 1) {
		if (write(dest_fd, stm32_wrapper, stm32_wrapper_size) != stm32_wrapper_size) {
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

		if (write(dest_fd, padding_zeros, padding) != padding) {
			fprintf(stderr, "Write error %s: %s\n", destname,
				strerror(errno));
			return -1;
		}
	}

	if (write(dest_fd, src_data, src_data_length) != src_data_length) {
		fprintf(stderr, "Write error on %s: %s\n", destname,
			strerror(errno));
		return -1;
	}

	if (wrapper_before == 0) {
		if (write(dest_fd, padding_zeros, padding) != padding) {
			fprintf(stderr, "Write error %s: %s\n", destname,
				strerror(errno));
			return -1;
		}

		if (write(dest_fd, stm32_wrapper, stm32_wrapper_size) != stm32_wrapper_size) {
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

	dest_size = dest_hdr_length + wrp_size + padding + src_data_length;

	ptr = mmap(0, dest_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   dest_fd, 0);

	if (ptr == MAP_FAILED) {
		fprintf(stderr, "Can't write %s\n", destname);
		return -1;
	}

	stm32image_update_header(ptr, dest_size, new_loadaddr, new_entry);

	stm32image_print_header(ptr);
	printf("Halt Address : 0x%08x\n", jmp_add);

	if (is_signed)
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

	while ((opt = getopt(argc, argv, "bfs:d:V")) != -1) {
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
		case 'V':
			fprintf(stderr, "stm32wrapper4dbg version " VERSION "\n");
			return 0;
		default:
			fprintf(stderr,
				"Usage: %1$s -s srcfile -d destfile [-b] [-f]\n"
				"       %1$s -V\n"
				"  Add a debug wrapper to a stm32 image.\n"
				"  If \"-b\" is not specified, the wrapper would be placed\n"
				"  after the last byte of the image.\n"
				"\nOptions:\n"
				"  -s srcfile   input image in stm32 file format\n"
				"  -d destfile  output image in stm32 file format\n"
				"  -b           place the wrapper before the image\n"
				"  -f           force re-adding the wrapper\n"
				"  -V           display tool version and quit\n",
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
