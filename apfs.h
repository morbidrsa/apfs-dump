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

#ifndef _APFS_H
#define _APFS_H

#include <linux/types.h>
#include "util.h"

enum apfs_obj_types {
	APFS_OBJ_NXSB		= 0x1,
	APFS_OBJ_BTROOT		= 0x2,
	APFS_OBJ_BTNODE		= 0x3,
	APFS_OBJ_SPACEMAN_HDR	= 0x5,
	APFS_OBJ_BITMAP_HDR	= 0x7,
	APFS_OBJ_BTREE_ROOT_PTR	= 0xb,
	APFS_OBJ_ID_MAPPING	= 0xc,
	APFS_OBJ_APSB		= 0xd,
};

enum apfs_obj_subtype {
	APFS_OBJ_SUB_NONE	= 0x00,
	APFS_OBJ_SUB_HISTORY	= 0x09,
	APFS_OBJ_SUB_LOCATION	= 0x0b,
	APFS_OBJ_SUB_FILES	= 0x0e,
	APFS_OBJ_SUB_EXTENTS	= 0x0f,
	APFS_OBJ_SUB_UNKOWN	= 0x10,
};

/* https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf Table 1 */
struct apfs_obj_header {
	__le64 checksum;
	__le64 oid;
	__le64 xid;
	__le16 type;
	__le16 flags;
	__le16 subtype;
	__le16 pad;
} __packed;

/* https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf Table 2 */
struct apfs_container_sb {
	struct apfs_obj_header hdr;
	__le32 magic;
	__le32 block_size;
	__le64 block_count;
	__le64 features;
	__le64 ro_compat_features;
	__le64 incompat_features;
	u8 uuid[16];
	__le64 next_oid;
	__le64 next_xid;
	__le32 xp_desc_blocks;
	__le32 xp_data_blocks;
	__le64 xp_desc_base;
	__le64 xp_data_base;
	__le32 xp_desc_len;
	__le32 xp_data_len;
	__le32 xp_desc_index;
	__le32 xp_desc_index_len;
	__le32 xp_data_index;
	__le32 xp_data_index_len;
	__le64 spaceman_oid;
	__le64 omap_oid;
	__le64 reaper_oid;
	__le32 unknown1;
	__le32 max_file_systems;
	__le64 fs_oid;
} __packed;

struct apfs_table_header {
	__le16 page;
	__le16 level;
	__le32 entries_cnt;
} __packed;

struct apfs_btree_root {
	struct apfs_obj_header hdr;
	struct apfs_table_header tbl;
	struct {
		__le32 type1;
		__le32 type2;
		__le64 blk;
	} entry[0xfd];
} __packed;

struct apfs_btree_header {
	__le16 flags; // Bit 0x4 : Fixed
        __le16 level; // 0 = Leaf
        __le32 entries_cnt;
        __le16 keys_offs;
        __le16 keys_len;
        __le16 free_offs;
        __le16 free_len;
        __le16 unk_30;
        __le16 unk_32;
        __le16 unk_34;
        __le16 unk_36;
} __packed;

struct apfs_node_id_map_key {
	__le64 nid;
	__le64 xid;
} __packed;

struct apfs_node_id_map_value {
	__le32 flags;
	__le32 size;
	__le64 blk;
} __packed;

#endif /* _APFS_H */
