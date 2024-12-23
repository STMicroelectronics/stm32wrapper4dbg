// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause

/*
 * Copyright (c) 2017-2024, STMicroelectronics - All Rights Reserved
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

#define VERSION			"5.0.0"

#define STM32MP25x_REVA		1

/* Magic = 'S' 'T' 'M' 0x32 */
#define HEADER_MAGIC		0x53544D32
#define HEADER_VERSION_V10	0x00010000
#define HEADER_VERSION_V20	0x00020000
#define HEADER_VERSION_V22	0x00020200
#define HEADER_VERSION_V23	0x00020300
#define PADDING_HEADER_MAGIC	0x5354FFFF
#define PADDING_HEADER_FLAG	(1 << 31)
#define BIN_TYPE_TF_A_IMAGE	0x10
#define BIN_TYPE_CM33_IMAGE	0x30

#define ARM_THUMB_ADDRESS(a)	((a) | 1)
#define ARM_THUMB_INSN(a)	((a) & ~1)
#define ALIGN(x, a)		(((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)	((x) & ~((a) - 1))
#define WRAPPER_ALIGNMENT	64UL

#define LOG_DEBUG(x ...)	do { if (verbose) printf(x); } while (0)
#define LOG_INFO(x ...)		printf(x)
#define LOG_ERROR(x ...)	fprintf(stderr, x)

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))

#define STM32_DUMMY_FW_LENGTH	16

static uint8_t stm32_mp1_ca7_wrapper[] = {
#include "wrapper_stm32mp15x_ca7.inc"
};

static uint8_t stm32_mp2_ca35_wrapper[] = {
#include "wrapper_stm32mp25x_ca35.inc"
};

static uint8_t stm32_mp2_cm33_wrapper[] = {
#include "wrapper_stm32mp25x_cm33.inc"
};

static uint8_t stm32_mp21_ca35_wrapper[] = {
#include "wrapper_stm32mp21x_ca35.inc"
};

static uint8_t stm32_mp21_cm33_wrapper[] = {
};

static bool verbose;

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
	const char *dummy_name;
	uint8_t *dummy_fw;
};

struct stm32_file {
	void *p;
	const struct stm32_soc *soc;
	int fd;
	size_t file_size;
	uint32_t file_header_length;
	uint32_t image_length;
	uint32_t image_entry_point;
	uint32_t load_address;
	uint32_t version_number;
	bool is_signed;
	bool is_encrypted;
};

/*
 * dummy code for armv7m thumb (CM33)
 *		.word	0xXXXX0200 // SP
 *		.word	0xXXXX0009 // reset
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *  label:
 *	e7fe	b label
 */
static uint8_t stm32_dummy_fw_m33_thumb[STM32_DUMMY_FW_LENGTH] = {
	0x00, 0x02, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0xfe, 0xe7,
};

/*
 * dummy code for aarch32 thumb (CA7)
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *	bf00	nop
 *  label:
 *	e7fe	b label
 */
static uint8_t stm32_dummy_fw_a32_thumb[STM32_DUMMY_FW_LENGTH] = {
	0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0xfe, 0xe7,
};

/*
 * dummy code for aarch64 (CA35)
 *	d503201f	nop
 *	d503201f	nop
 *	d503201f	nop
 *  label:
 *	14000000	b label
 */
static uint8_t stm32_dummy_fw_a64[STM32_DUMMY_FW_LENGTH] = {
	0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x00, 0x00, 0x00, 0x14,
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
		.dummy_name =		"dummy-mp13-ca7",
		.dummy_fw =		stm32_dummy_fw_a32_thumb,
	}, {
		.name =			"STM32MP15x Cortex-A7",
		.header_version =	HEADER_VERSION_V10,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x2FFC0000,
		.mem_end =		0x30000000,
		.wrapper =		stm32_mp1_ca7_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp1_ca7_wrapper),
		.wrapper_is_arm_thumb =	true,
		.dummy_name =		"dummy-mp15-ca7",
		.dummy_fw =		stm32_dummy_fw_a32_thumb,
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
		.dummy_name =		"dummy-mp25reva-ca35",
		.dummy_fw =		stm32_dummy_fw_a64,
	}, {
		.name =			"STM32MP25x Rev.A Cortex-M33",
		.header_version =	HEADER_VERSION_V20,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E080000,
		.mem_end =		0x0E0A0000,
		.wrapper =		stm32_mp2_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
		.dummy_name =		"dummy-mp25reva-cm33",
		.dummy_fw =		stm32_dummy_fw_m33_thumb,
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
		.dummy_name =		"dummy-mp25-ca35",
		.dummy_fw =		stm32_dummy_fw_a64,
	}, {
		.name =			"STM32MP2[35]x Cortex-M33",
		.header_version =	HEADER_VERSION_V22,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E080000,
		.mem_end =		0x0E0A0000,
		.wrapper =		stm32_mp2_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp2_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
		.dummy_name =		"dummy-mp25-cm33",
		.dummy_fw =		stm32_dummy_fw_m33_thumb,
	}, {
		.name =			"STM32MP21x Cortex-A35",
		.header_version =	HEADER_VERSION_V23,
		.binary_type =		BIN_TYPE_TF_A_IMAGE,
		.mem_start =		0x0E002640,
		.mem_end =		0x0E040000,
		.wrapper =		stm32_mp21_ca35_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp21_ca35_wrapper),
		.wrapper_is_arm_thumb =	false,
		.dummy_name =		"dummy-mp21-ca35",
		.dummy_fw =		stm32_dummy_fw_a64,
	}, {
		.name =			"STM32MP21x Cortex-M33",
		.header_version =	HEADER_VERSION_V23,
		.binary_type =		BIN_TYPE_CM33_IMAGE,
		.mem_start =		0x0E040000,
		.mem_end =		0x0E060000,
		.wrapper =		stm32_mp21_cm33_wrapper,
		.wrapper_size =		ARRAY_SIZE(stm32_mp21_cm33_wrapper),
		.wrapper_is_arm_thumb =	true,
		.dummy_name =		"dummy-mp21-cm33",
		.dummy_fw =		stm32_dummy_fw_m33_thumb,
	},
};

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

		if (binary_type == BIN_TYPE_CM33_IMAGE &&
		    image_length >= 8 &&
		    image_entry_point != __le32_to_cpu(*(uint32_t *)(p + header_length + 4))) {
			LOG_DEBUG("Image entry point mismatches reset vector\n");
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

static int stm32image_update_header(const struct stm32_file *f)
{
	struct stm32_header_v10 *h10 = f->p;
	struct stm32_header_v2x *h2x = f->p;
	struct stm32_header_v23 *h23 = f->p;
	uint8_t *p = f->p;
	uint32_t crc, extension_length;

	if (f->soc->binary_type == BIN_TYPE_CM33_IMAGE)
		*(uint32_t *)(p + f->file_header_length + 4) = __cpu_to_le32(f->image_entry_point);

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

static int stm32image_open_source_file(const char *srcname, int force, struct stm32_file *src)
{
	uint32_t src_hdr_length, src_data_length;
	struct stat sbuf;

	src->fd = open(srcname, O_RDONLY);
	if (src->fd == -1) {
		LOG_ERROR("Can't open %s: %s\n", srcname, strerror(errno));
		return -1;
	}

	if (fstat(src->fd, &sbuf) < 0) {
		return -1;
	}

	src->file_size = sbuf.st_size;
	if ((sbuf.st_mode & S_IFBLK) && (ioctl(src->fd, BLKGETSIZE64, &src->file_size) < 0)) {
		LOG_ERROR("Can't read size of %s\n", srcname);
		return -1;
	}

	src->p = mmap(NULL, src->file_size, PROT_READ, MAP_SHARED, src->fd, 0);
	if (src->p == MAP_FAILED) {
		LOG_ERROR("Can't read %s\n", srcname);
		return -1;
	}

	if (stm32image_check_hdr(src, src->file_size) < 0) {
		LOG_ERROR("Not a valid image file %s\n", srcname);
		return -1;
	}

	if (!src->soc->wrapper_size) {
		LOG_ERROR("Image \"%s\" not supported yet\n", src->soc->name);
		return -1;
	}

	src_hdr_length = src->file_header_length;
	src_data_length = src->image_length;

	if (src_hdr_length + src_data_length < src->file_size)
                LOG_INFO("Strip extra padding from input file\n");

	if (force == 0 && stm32image_check_wrapper(src) < 0) {
		LOG_ERROR("Wrapper already present in image file %s\n"
			  "Use flag \"-f\" to force re-adding the wrapper\n",
			  srcname);
		return -1;
	}

	if (src->is_encrypted) {
		LOG_ERROR("Image %s is encrypted. Unable to extract the content.\n",
			  srcname);
		return -1;
	}

	return 0;
}

static int stm32image_close_source_file(struct stm32_file *src)
{
	munmap(src->p, src->file_size);
	close(src->fd);

	return 0;
}

static int stm32image_dummy_source(struct stm32_file *src, const struct stm32_soc *soc)
{
	unsigned int header_length;

	switch (soc->header_version) {
	case HEADER_VERSION_V10:
		header_length = sizeof(struct stm32_header_v10);
		break;

	case HEADER_VERSION_V20:
	case HEADER_VERSION_V22:
		header_length = sizeof(struct stm32_header_v2x);
		break;

	case HEADER_VERSION_V23:
	default:
		header_length = sizeof(struct stm32_header_v23);
		break;
	};

	src->p =		  soc->dummy_fw - header_length;
	src->soc =		  soc;
	src->file_header_length = header_length;
	src->image_length =	  STM32_DUMMY_FW_LENGTH;
	src->load_address =	  soc->mem_start;
	src->version_number =	  0;
	src->is_signed =	  false;
	src->is_encrypted =	  false;

	if (soc->binary_type == BIN_TYPE_CM33_IMAGE) {
		uint32_t *fw = (uint32_t *)soc->dummy_fw;

		src->image_entry_point = soc->mem_start + __le32_to_cpu(fw[1]);

		fw[0] = __cpu_to_le32(soc->mem_start + __le32_to_cpu(fw[0])); // SP
		fw[1] = __cpu_to_le32(src->image_entry_point);                // reset
	} else {
		src->image_entry_point = soc->mem_start + (soc->wrapper_is_arm_thumb ? 1 : 0);
	}

	return 0;
}

static int stm32image_create_dest_file(const char *destname, int wrapper_before,
				       const struct stm32_file *src)
{
	struct stm32_file dst = { NULL, };
	uint32_t src_hdr_length, dest_hdr_length;
	unsigned char *src_data;
	uint32_t src_data_length, jmp_add, padding, wrp_loadaddr, wrp_size;
	uint32_t new_loadaddr, new_entry = 0;
	uint32_t loadaddr, entry;

	src_hdr_length = src->file_header_length;
	src_data = ((uint8_t *)src->p) + src_hdr_length;
	src_data_length = src->image_length;

	entry = src->image_entry_point;
	loadaddr = src->load_address;

	dst.fd = open(destname, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0666);
	if (dst.fd == -1) {
		LOG_ERROR("Can't open %s: %s\n", destname, strerror(errno));
		return -1;
	}

	dest_hdr_length = src_hdr_length;

	if (write(dst.fd, zero_buffer, dest_hdr_length) != dest_hdr_length) {
		LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
		return -1;
	}

	wrp_size = src->soc->wrapper_size + sizeof(jmp_add);
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

	new_entry = (src->soc->wrapper_is_arm_thumb) ? ARM_THUMB_ADDRESS(wrp_loadaddr) : wrp_loadaddr;

	jmp_add = __cpu_to_le32(entry);

	if (wrapper_before == 1) {
		if (write(dst.fd, src->soc->wrapper, src->soc->wrapper_size) != src->soc->wrapper_size) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dst.fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dst.fd, zero_buffer, padding) != padding) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}
	}

	if (write(dst.fd, src_data, src_data_length) != src_data_length) {
		LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
		return -1;
	}

	if (wrapper_before == 0) {
		if (write(dst.fd, zero_buffer, padding) != padding) {
			LOG_ERROR("Write error %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dst.fd, src->soc->wrapper, src->soc->wrapper_size) != src->soc->wrapper_size) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}

		if (write(dst.fd, &jmp_add, sizeof(jmp_add)) !=
		    sizeof(jmp_add)) {
			LOG_ERROR("Write error on %s: %s\n", destname, strerror(errno));
			return -1;
		}
	}

	dst.file_size = dest_hdr_length + wrp_size + padding + src_data_length;

	dst.p = mmap(0, dst.file_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   dst.fd, 0);

	if (dst.p == MAP_FAILED) {
		LOG_ERROR("Can't write %s\n", destname);
		return -1;
	}
	dst.soc = src->soc;
	dst.file_header_length = dest_hdr_length;
	dst.version_number =	src->version_number;
	dst.image_length =	wrp_size + padding + src_data_length;
	dst.image_entry_point =	new_entry;
	dst.load_address =	new_loadaddr;

	stm32image_update_header(&dst);

	stm32image_print_header(&dst);
	LOG_INFO("Halt Address : 0x%08x\n", jmp_add);

	if (src->is_signed)
		LOG_INFO("\nATTENTION:\n\tSource file was \"signed\"!\n"
			 "\tYou would need to sign the destination file \"%s\"\n",
			 destname);

	munmap(dst.p, dst.file_size);
	close(dst.fd);
	return 0;
}

int main(int argc, char *argv[])
{
	int opt, err, wrapper_before = 0, force = 0;
	char *dstname = NULL, *srcname = NULL;
	struct stm32_file src = { NULL, };

	while ((opt = getopt(argc, argv, "bfs:d:vVh")) != -1) {
		switch (opt) {
		case 'b':
			wrapper_before = 1;
			break;
		case 'f':
			force = 1;
			break;
		case 's':
			srcname = optarg;
			break;
		case 'd':
			dstname = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			LOG_ERROR("stm32wrapper4dbg version " VERSION "\n");
			return 0;
		case 'h':
		default:
			LOG_ERROR(
				"Usage: %1$s -s srcfile -d destfile [-b] [-f]\n"
				"       %1$s -V\n"
				"       %1$s -h\n"
				"  Add a debug wrapper to a stm32 image.\n"
				"  If \"-b\" is not specified, the wrapper would be placed\n"
				"  after the last byte of the image.\n"
				"\nOptions:\n"
				"  -s srcfile   input image in stm32 file format\n"
				"  -d destfile  output image in stm32 file format\n"
				"  -b           place the wrapper before the image\n"
				"  -f           force re-adding the wrapper\n"
				"  -v           verbose log\n"
				"  -V           display tool version and quit\n"
				"  -h           display this help and quit\n"
				"\nSpecial srcfile values:\n",
				argv[0]);
			for (unsigned int i = 0; i < ARRAY_SIZE(stm32_socs); i++)
				LOG_ERROR("%c \"%s\"", i ? ',' : ' ', stm32_socs[i].dummy_name);
			LOG_ERROR("\n");
			return -1;
		}
	}

	if (!srcname) {
		LOG_ERROR("Missing -s option\n");
		return -1;
	}

	if (!dstname) {
		LOG_ERROR("Missing -d option\n");
		return -1;
	}

	/* check for dummy source file (infinite loop firmware) */
	for (unsigned int i = 0; i < ARRAY_SIZE(stm32_socs); i++) {
		if (strcmp(srcname, stm32_socs[i].dummy_name))
			continue;

		stm32image_dummy_source(&src, &stm32_socs[i]);

		return stm32image_create_dest_file(dstname, wrapper_before, &src);
	}

	/* continue with real source file */
	err = stm32image_open_source_file(srcname, force, &src);
	if (err)
		return err;

	err = stm32image_create_dest_file(dstname, wrapper_before, &src);

	stm32image_close_source_file(&src);

	return err;
}
