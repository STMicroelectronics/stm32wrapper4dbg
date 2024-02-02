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

#define VERSION			"3.1.2"

#define STM32MP25x_REVA		1

/* Magic = 'S' 'T' 'M' 0x32 */
#define HEADER_MAGIC		0x53544D32
#define VER_MAJOR		2
#define VER_MINOR		1
#define VER_VARIANT		0
#define HEADER_VERSION_V1	0x1
#define HEADER_VERSION_V2	0x2
#define HEADER_VERSION_V10	0x00010000
#define HEADER_VERSION_V20	0x00020000
#define HEADER_VERSION_V22	0x00020200
#define HEADER_VERSION_V23	0x00020300
#define PADDING_HEADER_MAGIC	0x5354FFFF
#define PADDING_HEADER_FLAG	(1 << 31)
#define PADDING_HEADER_LENGTH	0x180
#define BIN_TYPE_TF_A_IMAGE	0x10
#define BIN_TYPE_CM33_IMAGE	0x30

#define ARM_THUMB_ADDRESS(a)	((a) | 1)
#define ARM_THUMB_INSN(a)	((a) & ~1)
#define ALIGN(x, a)		(((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)	((x) & ~((a) - 1))
#define WRAPPER_ALIGNMENT	64UL

#define STM32MP13X_SYSRAM_START	0x2ffe0000
#define STM32MP13X_SYSRAM_END	0x30000000

#define LOG_DEBUG(x ...)	do { if (verbose) printf(x); } while (0)
#define LOG_INFO(x ...)		printf(x)
#define LOG_ERROR(x ...)	fprintf(stderr, x)

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))

static uint8_t stm32_mp1_ca7_wrapper[] = {
#include "wrapper_stm32mp15x.inc"
};

static uint8_t stm32_mp2_ca35_wrapper[] = {
#include "wrapper_stm32mp25x.inc"
};

static uint8_t stm32_mp2_cm33_wrapper[] = {
};

static uint8_t stm32_mp21_ca35_wrapper[] = {
};

static uint8_t stm32_mp21_cm33_wrapper[] = {
};

static bool verbose;
static uint8_t *stm32_wrapper;
static unsigned int stm32_wrapper_size;
static const char *stm32_wrapper_string;
static int stm32_wrapper_is_arm_thumb;

struct stm32_header_v10 {
	uint32_t magic_number;
	uint8_t image_signature[64];
	uint32_t image_checksum;
	uint32_t header_version;
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

struct stm32_header_v2x {
	uint32_t magic_number;
	uint8_t image_signature[64];
	uint32_t image_checksum;
	uint32_t header_version;
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t reserved1;
	uint32_t load_address;
	uint32_t reserved2;
	uint32_t version_number;
	uint32_t extension_flags;
	uint32_t post_headers_length;
	uint32_t binary_type;
	uint8_t padding[16];
	uint32_t extension_header_type;
	uint32_t extension_header_length;
	uint8_t extension_padding[376];
};

struct stm32_header_v23 {
	uint32_t magic_number;
	uint8_t image_signature[96];
	uint32_t image_checksum;
	uint32_t header_version;
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t reserved1;
	uint32_t load_address;
	uint32_t reserved2;
	uint32_t version_number;
	uint32_t extension_flags;
	uint32_t post_headers_length;
	uint32_t binary_type;
	uint8_t padding[8];
	uint32_t non_secure_payload_length;
	uint32_t non_secure_payload_hash;
	uint32_t extension_header_type;
	uint32_t extension_header_length;
	uint8_t extension_padding[408];
};

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

/* big enough for padding and all header types */
static const uint8_t zero_buffer[2048];

struct stm32_soc {
	const char *name;
	uint32_t header_version;
	uint32_t binary_type;
	uint32_t mem_start;
	uint32_t mem_end;
	const uint8_t *wrapper;
	unsigned int wrapper_size;
	bool wrapper_is_arm_thumb;
};

struct stm32_file {
	void *p;
	const struct stm32_soc *soc;
	uint32_t file_header_length;
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t load_address;
	uint32_t version_number;
	bool is_signed;
	bool is_encrypted;
};

static const struct stm32_soc stm32_socs[] = {
	{
		.name =			"STM32MP13x Cortex-A7",
		.header_version =	HEADER_VERSION_V20,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x2FFE0000,
		.mem_end =		0x30000000,
		.wrapper =		stm32_mp1_ca7_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp1_ca7_wrapper),
		.wrapper_is_arm_thumb =	true,
	}, {
		.name =			"STM32MP15x Cortex-A7",
		.header_version =	HEADER_VERSION_V10,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x2FFC0000,
		.mem_end =		0x30000000,
		.wrapper =		stm32_mp1_ca7_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp1_ca7_wrapper),
		.wrapper_is_arm_thumb =	true,
	}, {
#ifdef STM32MP25x_REVA
		.name =			"STM32MP25x Rev.A Cortex-A35",
		.header_version =	HEADER_VERSION_V20,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x0E002600,
		.mem_end =		0x0E040000,
		.wrapper =		stm32_mp2_ca35_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_ca35_wrapper),
		.wrapper_is_arm_thumb =	false,
	}, {
		.name =			"STM32MP25x Rev.A Cortex-M33",
		.header_version =	HEADER_VERSION_V20,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E080000,
		.mem_end =		0x0E0A0000,
		.wrapper =		stm32_mp2_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
	}, {
#endif /* STM32MP25x_REVA */
		.name =			"STM32MP2[35]x Cortex-A35",
		.header_version =	HEADER_VERSION_V22,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x0E002600,
		.mem_end =		0x0E040000,
		.wrapper =		stm32_mp2_ca35_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_ca35_wrapper),
		.wrapper_is_arm_thumb =	false,
	}, {
		.name =			"STM32MP2[35]x Cortex-M33",
		.header_version =	HEADER_VERSION_V22,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E080000,
		.mem_end =		0x0E0A0000,
		.wrapper =		stm32_mp2_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
	}, {
		.name =			"STM32MP21x Cortex-A35",
		.header_version =	HEADER_VERSION_V23,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x0E002640,
		.mem_end =		0x0E040000,
		.wrapper =		stm32_mp21_ca35_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp21_ca35_wrapper),
		.wrapper_is_arm_thumb =	false,
	}, {
		.name =			"STM32MP21x Cortex-M33",
		.header_version =	HEADER_VERSION_V23,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E040000,
		.mem_end =		0x0E060000,
		.wrapper =		stm32_mp21_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp21_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
	},
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

static uint32_t stm32_checksum(const uint8_t *p, uint32_t len)
{
	uint32_t csum = 0;

	while (len > 0) {
		csum += *p;
		p++;
		len--;
	}

	return csum;
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

static int stm32image_check_hdr(struct stm32_file *f, uint32_t file_length)
{
	const struct stm32_header_v10 *h10 = f->p;
	const struct stm32_header_v2x *h2x = f->p;
	const struct stm32_header_v23 *h23 = f->p;
	const uint8_t *p = f->p;
	uint32_t header_length, magic_number, image_checksum, header_version;
	uint32_t image_length, image_entry_point;
	uint32_t load_address, reserved1, reserved2, version_number, flags, post_headers_length, binary_type;
	unsigned int padding_start, padding_size;
	bool is_signed, is_encrypted;
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(stm32_socs); i++) {
		LOG_DEBUG("Checking for soc \"%s\"\n", stm32_socs[i].name);

		switch (stm32_socs[i].header_version) {
		case HEADER_VERSION_V10:
			header_length = sizeof(*h10);
			break;
		case HEADER_VERSION_V20:
		case HEADER_VERSION_V22:
			header_length = sizeof(*h2x);
			break;
		case HEADER_VERSION_V23:
			header_length = sizeof(*h23);
			break;
		default:
			continue;
		}

		if (file_length < header_length) {
			LOG_DEBUG("File too small\n");
			continue;
		}

		switch (stm32_socs[i].header_version) {
		case HEADER_VERSION_V10:
			magic_number =		__be32_to_cpu(h10->magic_number);
			image_checksum =	__le32_to_cpu(h10->image_checksum);
			header_version =	__le32_to_cpu(h10->header_version);
			image_length =		__le32_to_cpu(h10->image_length);
			image_entry_point =	__le32_to_cpu(h10->image_entry_point);
			load_address =		__le32_to_cpu(h10->load_address);
			reserved1 =		h10->reserved1;
			reserved2 =		h10->reserved2;
			version_number =	__le32_to_cpu(h10->version_number);
			flags =			__le32_to_cpu(h10->option_flags);
			post_headers_length =	header_length;
			binary_type =		h10->binary_type;
			padding_start =		offsetof(typeof(*h10), padding);
			padding_size =		sizeof(h10->padding);
			is_signed =		(flags & 1) == 0;
			is_encrypted =		false;
			break;

		case HEADER_VERSION_V20:
		case HEADER_VERSION_V22:
			magic_number =		__be32_to_cpu(h2x->magic_number);
			image_checksum =	__le32_to_cpu(h2x->image_checksum);
			header_version =	__le32_to_cpu(h2x->header_version);
			image_length =		__le32_to_cpu(h2x->image_length);
			image_entry_point =	__le32_to_cpu(h2x->image_entry_point);
			load_address =		__le32_to_cpu(h2x->load_address);
			reserved1 =		h2x->reserved1;
			reserved2 =		h2x->reserved2;
			version_number =	__le32_to_cpu(h2x->version_number);
			flags =			__le32_to_cpu(h2x->extension_flags);
			post_headers_length =	__le32_to_cpu(h2x->post_headers_length) +
						offsetof(typeof(*h2x), extension_header_type);
			binary_type =		__le32_to_cpu(h2x->binary_type);
			padding_start =		offsetof(typeof(*h2x), padding);
			padding_size =		sizeof(h2x->padding);
			is_signed =		(flags & 1) != 0;
			is_encrypted =		(flags & 2) != 0;
			break;

		case HEADER_VERSION_V23:
		default:
			magic_number =		__be32_to_cpu(h23->magic_number);
			image_checksum =	__le32_to_cpu(h23->image_checksum);
			header_version =	__le32_to_cpu(h23->header_version);
			image_length =		__le32_to_cpu(h23->image_length);
			image_entry_point =	__le32_to_cpu(h23->image_entry_point);
			load_address =		__le32_to_cpu(h23->load_address);
			reserved1 =		h23->reserved1;
			reserved2 =		h23->reserved2;
			version_number =	__le32_to_cpu(h23->version_number);
			flags =			__le32_to_cpu(h23->extension_flags);
			post_headers_length =	__le32_to_cpu(h23->post_headers_length) +
						offsetof(typeof(*h23), extension_header_type);
			binary_type =		__le32_to_cpu(h23->binary_type);
			padding_start =		offsetof(typeof(*h23), padding);
			padding_size =		sizeof(h23->padding);
			is_signed =		(flags & 1) != 0;
			is_encrypted =		(flags & 2) != 0;
			break;
		}

		if (magic_number != HEADER_MAGIC) {
			LOG_DEBUG("Wrong header magic\n");
			continue;
		}

		if (header_version != stm32_socs[i].header_version) {
			LOG_DEBUG("Wrong header version\n");
			continue;
		}

		if (binary_type != stm32_socs[i].binary_type) {
			LOG_DEBUG("Wrong header binary type\n");
			continue;
		}

		if (file_length < header_length + image_length) {
			LOG_DEBUG("File too small\n");
			continue;
		}

		if (header_length != post_headers_length) {
			LOG_DEBUG("Wrong header size\n");
			continue;
		}

		if (image_checksum != stm32_checksum(p + header_length, image_length)) {
			LOG_DEBUG("Wrong image checksum\n");
			continue;
		}

		if (reserved1 || reserved2) {
			LOG_DEBUG("Wrong image, reserved fields not zero\n");
			continue;
		}

		for (j = 0; j < padding_size; j++)
			if (p[padding_start + j])
				break;

		if (j < padding_size) {
			LOG_DEBUG("Wrong image, padding not zero\n");
			continue;
		}

		if ((image_entry_point < load_address) ||
		    (image_entry_point >= load_address + image_length)) {
			LOG_DEBUG("Wrong image entry point\n");
			continue;
		}

		if ((load_address < stm32_socs[i].mem_start) ||
		    (load_address + image_length > stm32_socs[i].mem_end)) {
			LOG_DEBUG("Image doesn't fit in memory\n");
			continue;
		}

		f->soc =		&stm32_socs[i];
		f->file_header_length =	header_length;
		f->image_length =	image_length;
		f->image_entry_point =	image_entry_point;
		f->load_address =	load_address;
		f->version_number =	version_number;
		f->is_signed =		is_signed;
		f->is_encrypted =	is_encrypted;

		return 0;
	}

	return -1;
}

static int stm32image_check_hdr2(struct stm32_header *stm32hdr,
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

static int stm32image_check_wrapper(const struct stm32_file *f)
{
	uint32_t entry, offset;
	uint8_t *ptr;

	entry = ARM_THUMB_INSN(f->image_entry_point);

	offset = entry - f->load_address;
	if (offset + f->soc->wrapper_size + sizeof(uint32_t) > f->image_length)
		return 0;

	ptr = f->p;
	if (memcmp(ptr + f->file_header_length + offset, f->soc->wrapper, f->soc->wrapper_size))
		return 0;

	return -1;
}

static int stm32image_check_wrapper2(struct stm32_header *stm32hdr)
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

static void stm32image_print_header(const struct stm32_file *f)
{
	LOG_INFO("Image Type   : STMicroelectronics STM32 V%d.%d\n",
		 (f->soc->header_version >> 16) & 0xFF,
		 (f->soc->header_version >> 8) & 0xFF);
	LOG_INFO("Image Target : %s\n", f->soc->name);
	LOG_INFO("Image Size   : %u bytes\n", f->image_length);
	LOG_INFO("Image Load   : 0x%08x\n", f->load_address);
	LOG_INFO("Entry Point  : 0x%08x\n", f->image_entry_point);
	LOG_INFO("Version      : 0x%08x\n", f->version_number);
}

static void stm32image_print_header2(const void *ptr)
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

static int stm32image_update_header(const struct stm32_file *f)
{
	struct stm32_header_v10 *h10 = f->p;
	struct stm32_header_v2x *h2x = f->p;
	struct stm32_header_v23 *h23 = f->p;
	uint8_t *p = f->p;
	uint32_t crc, extension_length;

	crc = stm32_checksum(p + f->file_header_length, f->image_length);

	switch (f->soc->header_version) {
	case HEADER_VERSION_V10:
		h10->magic_number =		__cpu_to_be32(HEADER_MAGIC);
		h10->version_number =		__cpu_to_le32(f->version_number);
		h10->header_version =		__cpu_to_le32(f->soc->header_version);
		h10->binary_type =		f->soc->binary_type;
		h10->option_flags =		__cpu_to_le32(0x00000001);
		h10->ecdsa_algorithm =		__cpu_to_le32(1);
		h10->image_length =		__cpu_to_le32(f->image_length);
		h10->image_entry_point =	__cpu_to_le32(f->image_entry_point);
		h10->load_address =		__cpu_to_le32(f->load_address);
		h10->image_checksum =		__cpu_to_le32(crc);
		break;

	case HEADER_VERSION_V20:
	case HEADER_VERSION_V22:
		extension_length = sizeof(*h2x) - offsetof(typeof(*h2x), extension_header_type);
		h2x->magic_number =		__cpu_to_be32(HEADER_MAGIC);
		h2x->version_number =		__cpu_to_le32(f->version_number);
		h2x->header_version =		__cpu_to_le32(f->soc->header_version);
		h2x->binary_type =		__cpu_to_le32(f->soc->binary_type);
		h2x->extension_flags =		__cpu_to_le32(PADDING_HEADER_FLAG);
		h2x->post_headers_length =	__cpu_to_le32(extension_length);
		h2x->extension_header_type =	__cpu_to_be32(PADDING_HEADER_MAGIC);
		h2x->extension_header_length =	__cpu_to_le32(extension_length);
		h2x->image_length =		__cpu_to_le32(f->image_length);
		h2x->image_entry_point =	__cpu_to_le32(f->image_entry_point);
		h2x->load_address =		__cpu_to_le32(f->load_address);
		h2x->image_checksum =		__cpu_to_le32(crc);
		break;

	case HEADER_VERSION_V23:
	default:
		extension_length = sizeof(*h23) - offsetof(typeof(*h23), extension_header_type);
		h23->magic_number =		__cpu_to_be32(HEADER_MAGIC);
		h23->version_number =		__cpu_to_le32(f->version_number);
		h23->header_version =		__cpu_to_le32(f->soc->header_version);
		h23->binary_type =		__cpu_to_le32(f->soc->binary_type);
		h23->extension_flags =		__cpu_to_le32(PADDING_HEADER_FLAG);
		h23->post_headers_length =	__cpu_to_le32(extension_length);
		h23->extension_header_type =	__cpu_to_be32(PADDING_HEADER_MAGIC);
		h23->extension_header_length =	__cpu_to_le32(extension_length);
		h23->image_length =		__cpu_to_le32(f->image_length);
		h23->image_entry_point =	__cpu_to_le32(f->image_entry_point);
		h23->load_address =		__cpu_to_le32(f->load_address);
		h23->image_checksum =		__cpu_to_le32(crc);
		break;
	}

	return 0;
}

static int stm32image_update_header2(void *ptr, uint32_t file_size,
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
	struct stm32_file src = { NULL, };
	struct stm32_file dst = { NULL, };
	int src_fd, dest_fd;
	struct stat sbuf;
	uint8_t *ptr;
	uint32_t src_hdr_length, dest_hdr_length;
	unsigned char *src_data;
	size_t src_size, dest_size;
	uint32_t src_data_length, jmp_add, padding, wrp_loadaddr, wrp_size;
	uint32_t new_loadaddr, new_entry = 0;
	uint32_t loadaddr, entry;

	src_fd = open(srcname, O_RDONLY);
	if (src_fd == -1) {
		LOG_ERROR("Can't open %s: %s\n", srcname, strerror(errno));
		return -1;
	}

	if (fstat(src_fd, &sbuf) < 0) {
		return -1;
	}

	src_size = sbuf.st_size;
	if ((sbuf.st_mode & S_IFBLK) && (ioctl(src_fd, BLKGETSIZE64, &src_size) < 0)) {
		LOG_ERROR("Can't read size of %s\n", srcname);
		return -1;
	}

	ptr = mmap(NULL, src_size, PROT_READ, MAP_SHARED, src_fd, 0);
	if (ptr == MAP_FAILED) {
		LOG_ERROR("Can't read %s\n", srcname);
		return -1;
	}
	src.p = ptr;

	if (stm32image_check_hdr(&src, src_size) < 0) {
		LOG_ERROR("Not a valid image file %s\n", srcname);
		return -1;
	}

	src_hdr_length = src.file_header_length;
	src_data = ptr + src_hdr_length;
	src_data_length = src.image_length;

	if (src_hdr_length + src_data_length < src_size)
                LOG_INFO("Strip extra padding from input file\n");

	if (force == 0 && stm32image_check_wrapper(&src) < 0) {
		LOG_ERROR("Wrapper already present in image file %s\n"
			  "Use flag \"-f\" to force re-adding the wrapper\n",
			  srcname);
		return -1;
	}

	entry = src.image_entry_point;
	loadaddr = src.load_address;

	if (src.is_encrypted) {
		LOG_ERROR("Image %s is encrypted. Unable to extract the content.\n",
			  srcname);
		return -1;
	}

	dest_fd = open(destname, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0666);
	if (dest_fd == -1) {
		LOG_ERROR("Can't open %s: %s\n", destname, strerror(errno));
		return -1;
	}

	dest_hdr_length = src_hdr_length;

	if (write(dest_fd, zero_buffer, dest_hdr_length) != dest_hdr_length) {
		LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
		return -1;
	}

	wrp_size = src.soc->wrapper_size + sizeof(jmp_add);
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

	new_entry = (src.soc->wrapper_is_arm_thumb) ? ARM_THUMB_ADDRESS(wrp_loadaddr) : wrp_loadaddr;

	jmp_add = __cpu_to_le32(entry);

	if (wrapper_before == 1) {
		if (write(dest_fd, src.soc->wrapper, src.soc->wrapper_size) != src.soc->wrapper_size) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dest_fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dest_fd, zero_buffer, padding) != padding) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}
	}

	if (write(dest_fd, src_data, src_data_length) != src_data_length) {
		LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
		return -1;
	}

	if (wrapper_before == 0) {
		if (write(dest_fd, zero_buffer, padding) != padding) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dest_fd, src.soc->wrapper, src.soc->wrapper_size) != src.soc->wrapper_size) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dest_fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}
	}

	munmap((void *)ptr, src_size);
	close(src_fd);

	dest_size = dest_hdr_length + wrp_size + padding + src_data_length;

	ptr = mmap(0, dest_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   dest_fd, 0);

	if (ptr == MAP_FAILED) {
		LOG_ERROR("Can't write %s\n", destname);
		return -1;
	}
	dst.p = ptr;
	dst.soc = src.soc;
	dst.file_header_length = dest_hdr_length;
	dst.version_number =	src.version_number;
	dst.image_length =	wrp_size + padding + src_data_length;
	dst.image_entry_point =	new_entry;
	dst.load_address =	new_loadaddr;

	stm32image_update_header(&dst);

	stm32image_print_header(&dst);
	LOG_INFO("Halt Address : 0x%08x\n", jmp_add);

	if (src.is_signed)
		LOG_INFO("\nATTENTION:\n\tSource file \"%s\" was \"signed\"!\n"
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

	while ((opt = getopt(argc, argv, "bfs:d:vV")) != -1) {
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
		case 'v':
			verbose = true;
			break;
		case 'V':
			LOG_ERROR("stm32wrapper4dbg version " VERSION "\n");
			return 0;
		default:
			LOG_ERROR(
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
				"  -v           verbose log\n"
				"  -V           display tool version and quit\n",
				argv[0]);
			return -1;
		}
	}

	if (!src) {
		LOG_ERROR("Missing -s option\n");
		return -1;
	}

	if (!dest) {
		LOG_ERROR("Missing -d option\n");
		return -1;
	}

	err = stm32image_create_header_file(src, dest, wrapper_before, force);

	return err;
}
