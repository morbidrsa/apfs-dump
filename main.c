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
#include <stdint.h>

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

struct node_info {
	__le32 flags;
	__le32 size;
	__le64 bid;
};

struct apfs_nid_map_key {
	__le64 nid;
	__le64 xid;
} __packed;


struct btree_node {
	uint16_t keys_start;
	uint16_t vals_start;

	uint64_t parent;
	uint64_t blk;

	struct apfs_obj_header *ohdr;
	struct apfs_btree_header *bt;
};

struct apfs_btree_entry_fixed {
	__le16 key_offs;
	__le16 val_offs;
} __packed;

struct btree_node_fixed {
	uint16_t keys_start;
	uint16_t vals_start;

	uint64_t parent;
	uint64_t blk;

	struct apfs_obj_header *ohdr;
	struct apfs_btree_header *bt;
	struct apfs_btree_entry_fixed* entries;
};

struct apfs_bt_footer {
	__le32 unk_FD8;
        __le32 unk_FDC; // 0x1000 - Node Size?
        __le32 min_key_size; // Key Size - or 0
        __le32 min_val_size; // Value Size - or 0
        __le32 max_key_size; // (Max) Key Size - or 0
        __le32 max_val_size; // (Max) Value Size - or 0
        __le64 entries_cnt; // Total entries in B*-Tree
        __le64 nodes_cnt; // Total nodes in B*-Tree
} __packed;

static struct btree_node_fixed *btree_create_fixed_node(void *buf, size_t size,  uint64_t parent, __le64 blk)
{
	struct btree_node_fixed *node;

	node = malloc(sizeof(*node));
	if (node) {
		struct apfs_obj_header *ohdr = buf;;
		struct apfs_btree_header *bt = buf + sizeof(struct apfs_obj_header);

		node->parent = parent;
		node->blk = blk;

		node->ohdr = ohdr;
		node->bt = bt;

		node->keys_start = 0x38 + bt->keys_len;
		node->vals_start = (parent != 0) ? size : size - sizeof(struct apfs_bt_footer);

		node->entries = buf + 0x38;

		printf("Fixed BTree Entry:\n");
		printf("\tparent: 0x%llx\n", (unsigned long long) node->parent);
		printf("\tblock: 0x%llx\n", (unsigned long long) node->blk);
		printf("\tkeys_start: 0x%x\n", node->keys_start);
		printf("\tvals_start: 0x%x\n", node->vals_start);
		printf("\tnode level: %d\n", node->bt->level);
	}

	return node;
}

static struct btree_node_fixed *read_btree(int fd, __le64 blk)
{
	struct apfs_btree_root *root;
	struct btree_node_fixed *root_node;
	void *buf;

	buf = malloc(SZ_4K);
	if (!buf) {
		perror("malloc");
		return NULL;
	}

	pread(fd, buf, SZ_4K, blk * SZ_4K);

	root = buf;
	print_objhdr(&root->hdr);
	printf("Btree Root:\n");
	printf("\tpage: 0x%x\n", root->tbl.page);
	printf("\tlevel: 0x%x\n", root->tbl.level);
	printf("\tentries_cnt: 0x%x\n", root->tbl.entries_cnt);

	root_node = btree_create_fixed_node(buf, SZ_4K, 0, blk);
	if (!root_node) {
		perror("malloc");
		goto free_buf;
	}

	return root_node;

free_buf:
	free(buf);
	return NULL;
}

static struct btree_node_fixed *read_omap(int fd, __le64 omap_oid)
{
	struct apfs_btree_root *btree;
	__le64 blk;
	void *buf;

	buf = malloc(SZ_4K);
	if (!buf) {
		perror("malloc");
		return NULL;
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


	blk = btree->entry[0].blk;
	free(buf);

	return read_btree(fd, blk);
}

static int read_image(char *path)
{
	struct apfs_obj_header *objhdr;
	struct btree_node_fixed *omap_root;
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

	if (!omap_oid)
		goto free_buf;

	/* read the OMAP block */
	omap_root = read_omap(fd, omap_oid);
	if (!omap_root)
		goto free_buf;

/* free_omap_root: */
	free(omap_root);
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
