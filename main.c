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

#define _POSIX_C_SOURCE 200809L

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

static struct objtypes {
	__le16 type;
	char *name;
} objtypes[] = {
	{ APFS_OBJ_NXSB,		"Container Superblock (NXSB)" },
	{ APFS_OBJ_BTROOT,		"BTree Root" },
	{ APFS_OBJ_BTNODE,		"BTree Node" },
	{ APFS_OBJ_SPACEMAN_HDR,	"Spaceman Header"},
	{ APFS_OBJ_BITMAP_HDR,		"Bitmap Header" },
	{ APFS_OBJ_BTREE_ROOT_PTR,	"BTree Root Ptr" },
	{ APFS_OBJ_ID_MAPPING,		"ID Mapping" },
	{ APFS_OBJ_APSB,		"Volume Superblock (APSB)" },
	{ 0, NULL },
};

static struct subtypes {
	__le16 subtype;
	char *name;
} subtypes[] = {
	{ APFS_OBJ_SUB_NONE,  		"No Subtype" },
	{ APFS_OBJ_SUB_HISTORY,		"History" },
	{ APFS_OBJ_SUB_LOCATION,	"Location" },
	{ APFS_OBJ_SUB_FILES,		"Files"	},
	{ APFS_OBJ_SUB_EXTENTS,		"Extents" },
	{ APFS_OBJ_SUB_UNKOWN,		"Unknown" },
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

	for (i = 0; i < ARRAY_SIZE(objtypes); i++) {
		if (objtypes[i].type == type)
			return objtypes[i].name;
	}

	return "Unknown";
}

static char *subtype2str(__le16 type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(subtypes); i++) {
		if (subtypes[i].subtype == type)
			return subtypes[i].name;
	}

	return "Unknown";
}

static void print_objhdr(struct apfs_obj_header *objhdr)
{
	printf("block header:\n");
	printf("\tchecksum: 0x%llx\n", objhdr->checksum);
	printf("\tnid: 0x%llx\n", objhdr->oid);
	printf("\txid: 0x%llx\n", objhdr->xid);
	printf("\ttype: 0x%x (%s)\n", objhdr->type, blktype2string(objhdr->type));
	printf("\tflags: 0x%x\n", objhdr->flags);
	printf("\tsubtype: 0x%x (%s)\n", objhdr->subtype,
	       subtype2str(objhdr->subtype));
}

static __le64 container_sb_get_omap_oid(void *buf)
{
	struct apfs_container_sb *nxsb = buf;

	return nxsb->omap_oid;
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
	printf("\tCheckpoint descriptor base offset: 0x%llx\n",
	       nxsb->xp_desc_base);
	printf("\tCheckpoint data base offset: 0x%llx\n", nxsb->xp_data_base);
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

static void read_omap(int fd, __le64 omap_oid)
{
	struct apfs_btree_root *btree;
	void *buf;

	buf = malloc(SZ_4K);
	if (!buf) {
		perror("malloc");
		return;
	}

	pread(fd, buf, SZ_4K, omap_oid * SZ_4K);
	/* XXX Error handling */

	btree = buf;
	print_objhdr(&btree->hdr);
	printf("OMAP BTree Root Ptr:\n");
	printf("\tpage: 0x%x\n", btree->tbl.page);
	printf("\tlevel: 0x%x\n", btree->tbl.level);
	printf("\tentries: 0x%x\n", btree->tbl.entries_cnt);
	printf("\tentry[0].type1: 0x%x\n", btree->entry[0].type1);
	printf("\tentry[0].type2: 0x%x\n", btree->entry[0].type2);
	printf("\tentry[0].blk: 0x%llx\n", btree->entry[0].blk);

	free(buf);
}

static int read_image(char *path)
{
	struct apfs_obj_header *objhdr;
	__le64 omap_oid = 0;
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

	objhdr = buf;
	print_objhdr(objhdr);
	switch (objhdr->type) {
	case APFS_OBJ_NXSB:
		print_container_sb(buf);
		omap_oid = container_sb_get_omap_oid(buf);
		break;
	default:
		break;
	}

	if (omap_oid)
		/* read the OMAP block */
		read_omap(fd, omap_oid);

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
