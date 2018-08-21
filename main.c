// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Johannes Thumshirn
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/types.h>

#include "util.h"
#include "apfs.h"

#define SZ_4K 4096

static struct blktypes {
	__le16 type;
	char *name;
} blktypes[] = {
	{ APFS_BLK_NXSB,		"Container Superblock (NXSB)" },
	{ APFS_BLK_BTROOT,		"BTree Root" },
	{ APFS_BLK_BTNODE,		"BTree Node" },
	{ APFS_BLK_SPACEMAN_HDR,	"Spaceman Header"},
	{ APFS_BLK_BITMAP_HDR,		"Bitmap Header" },
	{ APFS_BLK_BTREE_ROOT_PTR,	"BTree Root Ptr" },
	{ APFS_BLK_ID_MAPPING,		"ID Mapping" },
	{ APFS_BLK_APSB,		"Volume Superblock (APSB)" },
	{ 0, NULL },
};

#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))

void uuid_bin2str(unsigned char *bin, char *str)
{
	const u8 uuid_chars[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8,
				   9, 10, 11, 12, 13, 14, 15};
	int i;

	for (i = 0; i < 16; i++) {
		sprintf(str, "%02x", bin[uuid_chars[i]]);
		str += 2;
		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			*str++ = '-';
			break;
		default:
			break;
		}
	}
}

static char *blktype2string(__le16 type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(blktypes); i++) {
		if (blktypes[i].type == type)
			return blktypes[i].name;
	}

	return "Unknown";
}

static void print_blkhdr(struct apfs_block_header *blkhdr)
{
	printf("block header:\n");
	printf("\tchecksum: 0x%llx\n", blkhdr->checksum);
	printf("\tnid: 0x%llx\n", blkhdr->oid);
	printf("\txid: 0x%llx\n", blkhdr->xid);
	printf("\ttype: 0x%x (%s)\n", blkhdr->type, blktype2string(blkhdr->type));
	printf("\tflags: 0x%x\n", blkhdr->flags);
	printf("\tsubtype: 0x%x\n", blkhdr->subtype);
}

static void print_container_sb(void *buf)
{
	struct apfs_container_sb *nxsb = buf;
	char uuid[128];

	uuid_bin2str(nxsb->uuid, uuid);

	printf("Container Super Block (NXSB):\n");
	printf("\tmagic: 0x%x\n", nxsb->magic);
	printf("\tblock size: 0x%x\n", nxsb->block_size);
	printf("\tblock count: 0x%llx\n", nxsb->block_count);
	printf("\tfeatures: 0x%llx\n", nxsb->features);
	printf("\tread-only compatible features: 0x%llx\n",
	       nxsb->ro_compat_features);
	printf("\tincompatible features: 0x%llx\n", nxsb->incompat_features);
	printf("\tUUID: %s\n", uuid);
	printf("\tnext object ID: 0x%llx\n", nxsb->next_oid);
	printf("\tnext transaction ID: 0x%llx\n", nxsb->next_xid);
	printf("\tCheckpoint descriptor blocks: 0x%x\n", nxsb->xp_desc_blocks);
	printf("\tCheckpoint data blocks: 0x%x\n", nxsb->xp_data_blocks);
	printf("\tCheckpoint descriptor base offset: 0x%x\n",
	       nxsb->xp_desc_base);
	printf("\tCheckpoint data base offset: 0x%x\n", nxsb->xp_data_base);
	printf("\tCheckpoint descriptor length: 0x%x\n", nxsb->xp_desc_len);
	printf("\tCheckpoint data length: 0x%x\n", nxsb->xp_data_len);
	printf("\tCheckpoint descriptor index: 0x%x\n", nxsb->xp_desc_index);
	printf("\tCheckpoint descriptor index length: 0x%x\n",
	       nxsb->xp_desc_index_len);
	printf("\tCheckpoint data index: 0x%x\n", nxsb->xp_data_index);
	printf("\tCheckpoint data index length: 0x%x\n",
	       nxsb->xp_data_index_len);
	printf("\tSpace Manager OID: 0x%llx\n", nxsb->spaceman_oid);
	printf("\tObject Map OID: 0x%llx\n", nxsb->omap_oid);
	printf("\tReaper OID: 0x%llx\n", nxsb->reaper_oid);
	printf("\tMaximum File Systems: 0x%x\n", nxsb->max_file_systems);
	printf("\tFile system OID: 0x%llx\n", nxsb->fs_oid);
}

static int read_image(char *path)
{
	struct apfs_block_header *blkhdr;
	ssize_t bytes;
	int ret = 0;
	void *buf;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	buf = malloc(SZ_4K);
	if (!buf) {
		perror("malloc");
		ret = 1;
		goto close_fd;
	}

	/* read the block header of the container superblock */
	bytes = read(fd, buf, SZ_4K);
	if (bytes <= 0){
		perror("read");
		ret = 1;
		goto free_buf;
	}

	blkhdr = buf;
	print_blkhdr(blkhdr);
	switch (blkhdr->type) {
	case APFS_BLK_NXSB:
		print_container_sb(buf);
		break;
	default:
		break;
	}

free_buf:
	free(buf);
close_fd:
	close(fd);

	return ret;
}

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s image\n", basename(progname));
}

int main(int argc, char **argv)
{
	int ret;

	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ret = read_image(argv[1]);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
