/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_PRM_H_
#define RTE_PMD_MLX5_PRM_H_

#include <assert.h>

/* Verbs header. */
/* ISO C doesn't support unnamed structs/unions, disabling -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/mlx5dv.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

#include <rte_vect.h>
#include "mlx5_autoconf.h"

/* RSS hash key size. */
#define MLX5_RSS_HASH_KEY_LEN 40

/* Get CQE owner bit. */
#define MLX5_CQE_OWNER(op_own) ((op_own) & MLX5_CQE_OWNER_MASK)

/* Get CQE format. */
#define MLX5_CQE_FORMAT(op_own) (((op_own) & MLX5E_CQE_FORMAT_MASK) >> 2)

/* Get CQE opcode. */
#define MLX5_CQE_OPCODE(op_own) (((op_own) & 0xf0) >> 4)

/* Get CQE solicited event. */
#define MLX5_CQE_SE(op_own) (((op_own) >> 1) & 1)

/* Invalidate a CQE. */
#define MLX5_CQE_INVALIDATE (MLX5_CQE_INVALID << 4)

/* Maximum number of packets a multi-packet WQE can handle. */
#define MLX5_MPW_DSEG_MAX 5

/* WQE DWORD size */
#define MLX5_WQE_DWORD_SIZE 16

/* WQE size */
#define MLX5_WQE_SIZE (4 * MLX5_WQE_DWORD_SIZE)

/* Max size of a WQE session. */
#define MLX5_WQE_SIZE_MAX 960U

/* Compute the number of DS. */
#define MLX5_WQE_DS(n) \
	(((n) + MLX5_WQE_DWORD_SIZE - 1) / MLX5_WQE_DWORD_SIZE)

/* Room for inline data in multi-packet WQE. */
#define MLX5_MWQE64_INL_DATA 28

/* Default minimum number of Tx queues for inlining packets. */
#define MLX5_EMPW_MIN_TXQS 8

/* Default max packet length to be inlined. */
#define MLX5_EMPW_MAX_INLINE_LEN (4U * MLX5_WQE_SIZE)


#define MLX5_OPC_MOD_ENHANCED_MPSW 0
#define MLX5_OPCODE_ENHANCED_MPSW 0x29

/* CQE value to inform that VLAN is stripped. */
#define MLX5_CQE_VLAN_STRIPPED (1u << 0)

/* IPv4 options. */
#define MLX5_CQE_RX_IP_EXT_OPTS_PACKET (1u << 1)

/* IPv6 packet. */
#define MLX5_CQE_RX_IPV6_PACKET (1u << 2)

/* IPv4 packet. */
#define MLX5_CQE_RX_IPV4_PACKET (1u << 3)

/* TCP packet. */
#define MLX5_CQE_RX_TCP_PACKET (1u << 4)

/* UDP packet. */
#define MLX5_CQE_RX_UDP_PACKET (1u << 5)

/* IP is fragmented. */
#define MLX5_CQE_RX_IP_FRAG_PACKET (1u << 7)

/* L2 header is valid. */
#define MLX5_CQE_RX_L2_HDR_VALID (1u << 8)

/* L3 header is valid. */
#define MLX5_CQE_RX_L3_HDR_VALID (1u << 9)

/* L4 header is valid. */
#define MLX5_CQE_RX_L4_HDR_VALID (1u << 10)

/* Outer packet, 0 IPv4, 1 IPv6. */
#define MLX5_CQE_RX_OUTER_PACKET (1u << 1)

/* Tunnel packet bit in the CQE. */
#define MLX5_CQE_RX_TUNNEL_PACKET (1u << 0)

/* Inner L3 checksum offload (Tunneled packets only). */
#define MLX5_ETH_WQE_L3_INNER_CSUM (1u << 4)

/* Inner L4 checksum offload (Tunneled packets only). */
#define MLX5_ETH_WQE_L4_INNER_CSUM (1u << 5)

/* Outer L4 type is TCP. */
#define MLX5_ETH_WQE_L4_OUTER_TCP  (0u << 5)

/* Outer L4 type is UDP. */
#define MLX5_ETH_WQE_L4_OUTER_UDP  (1u << 5)

/* Outer L3 type is IPV4. */
#define MLX5_ETH_WQE_L3_OUTER_IPV4 (0u << 4)

/* Outer L3 type is IPV6. */
#define MLX5_ETH_WQE_L3_OUTER_IPV6 (1u << 4)

/* Inner L4 type is TCP. */
#define MLX5_ETH_WQE_L4_INNER_TCP (0u << 1)

/* Inner L4 type is UDP. */
#define MLX5_ETH_WQE_L4_INNER_UDP (1u << 1)

/* Inner L3 type is IPV4. */
#define MLX5_ETH_WQE_L3_INNER_IPV4 (0u << 0)

/* Inner L3 type is IPV6. */
#define MLX5_ETH_WQE_L3_INNER_IPV6 (1u << 0)

/* Is flow mark valid. */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#define MLX5_FLOW_MARK_IS_VALID(val) ((val) & 0xffffff00)
#else
#define MLX5_FLOW_MARK_IS_VALID(val) ((val) & 0xffffff)
#endif

/* INVALID is used by packets matching no flow rules. */
#define MLX5_FLOW_MARK_INVALID 0

/* Maximum allowed value to mark a packet. */
#define MLX5_FLOW_MARK_MAX 0xfffff0

/* Default mark value used when none is provided. */
#define MLX5_FLOW_MARK_DEFAULT 0xffffff

/* Maximum number of DS in WQE. */
#define MLX5_DSEG_MAX 63

/* Subset of struct mlx5_wqe_eth_seg. */
struct mlx5_wqe_eth_seg_small {
	uint32_t rsvd0;
	uint8_t	cs_flags;
	uint8_t	rsvd1;
	uint16_t mss;
	uint32_t flow_table_metadata;
	uint16_t inline_hdr_sz;
	uint8_t inline_hdr[2];
} __rte_aligned(MLX5_WQE_DWORD_SIZE);

struct mlx5_wqe_inl_small {
	uint32_t byte_cnt;
	uint8_t raw;
} __rte_aligned(MLX5_WQE_DWORD_SIZE);

struct mlx5_wqe_ctrl {
	uint32_t ctrl0;
	uint32_t ctrl1;
	uint32_t ctrl2;
	uint32_t ctrl3;
} __rte_aligned(MLX5_WQE_DWORD_SIZE);

/* Small common part of the WQE. */
struct mlx5_wqe {
	uint32_t ctrl[4];
	struct mlx5_wqe_eth_seg_small eseg;
};

/* Vectorize WQE header. */
struct mlx5_wqe_v {
	rte_v128u32_t ctrl;
	rte_v128u32_t eseg;
};

/* WQE. */
struct mlx5_wqe64 {
	struct mlx5_wqe hdr;
	uint8_t raw[32];
} __rte_aligned(MLX5_WQE_SIZE);

/* MPW mode. */
enum mlx5_mpw_mode {
	MLX5_MPW_DISABLED,
	MLX5_MPW,
	MLX5_MPW_ENHANCED, /* Enhanced Multi-Packet Send WQE, a.k.a MPWv2. */
};

/* MPW session status. */
enum mlx5_mpw_state {
	MLX5_MPW_STATE_OPENED,
	MLX5_MPW_INL_STATE_OPENED,
	MLX5_MPW_ENHANCED_STATE_OPENED,
	MLX5_MPW_STATE_CLOSED,
};

/* MPW session descriptor. */
struct mlx5_mpw {
	enum mlx5_mpw_state state;
	unsigned int pkts_n;
	unsigned int len;
	unsigned int total_len;
	volatile struct mlx5_wqe *wqe;
	union {
		volatile struct mlx5_wqe_data_seg *dseg[MLX5_MPW_DSEG_MAX];
		volatile uint8_t *raw;
	} data;
};

/* WQE for Multi-Packet RQ. */
struct mlx5_wqe_mprq {
	struct mlx5_wqe_srq_next_seg next_seg;
	struct mlx5_wqe_data_seg dseg;
};

#define MLX5_MPRQ_LEN_MASK 0x000ffff
#define MLX5_MPRQ_LEN_SHIFT 0
#define MLX5_MPRQ_STRIDE_NUM_MASK 0x3fff0000
#define MLX5_MPRQ_STRIDE_NUM_SHIFT 16
#define MLX5_MPRQ_FILLER_MASK 0x80000000
#define MLX5_MPRQ_FILLER_SHIFT 31

#define MLX5_MPRQ_STRIDE_SHIFT_BYTE 2

/* CQ element structure - should be equal to the cache line size */
struct mlx5_cqe {
#if (RTE_CACHE_LINE_SIZE == 128)
	uint8_t padding[64];
#endif
	uint8_t pkt_info;
	uint8_t rsvd0;
	uint16_t wqe_id;
	uint8_t rsvd3[8];
	uint32_t rx_hash_res;
	uint8_t rx_hash_type;
	uint8_t rsvd1[11];
	uint16_t hdr_type_etc;
	uint16_t vlan_info;
	uint8_t rsvd2[12];
	uint32_t byte_cnt;
	uint64_t timestamp;
	uint32_t sop_drop_qpn;
	uint16_t wqe_counter;
	uint8_t rsvd4;
	uint8_t op_own;
};

/* Adding direct verbs to data-path. */

/* CQ sequence number mask. */
#define MLX5_CQ_SQN_MASK 0x3

/* CQ sequence number index. */
#define MLX5_CQ_SQN_OFFSET 28

/* CQ doorbell index mask. */
#define MLX5_CI_MASK 0xffffff

/* CQ doorbell offset. */
#define MLX5_CQ_ARM_DB 1

/* CQ doorbell offset*/
#define MLX5_CQ_DOORBELL 0x20

/* CQE format value. */
#define MLX5_COMPRESSED 0x3

/* The field of packet to be modified. */
enum mlx5_modificaiton_field {
	MLX5_MODI_OUT_SMAC_47_16 = 1,
	MLX5_MODI_OUT_SMAC_15_0,
	MLX5_MODI_OUT_ETHERTYPE,
	MLX5_MODI_OUT_DMAC_47_16,
	MLX5_MODI_OUT_DMAC_15_0,
	MLX5_MODI_OUT_IP_DSCP,
	MLX5_MODI_OUT_TCP_FLAGS,
	MLX5_MODI_OUT_TCP_SPORT,
	MLX5_MODI_OUT_TCP_DPORT,
	MLX5_MODI_OUT_IPV4_TTL,
	MLX5_MODI_OUT_UDP_SPORT,
	MLX5_MODI_OUT_UDP_DPORT,
	MLX5_MODI_OUT_SIPV6_127_96,
	MLX5_MODI_OUT_SIPV6_95_64,
	MLX5_MODI_OUT_SIPV6_63_32,
	MLX5_MODI_OUT_SIPV6_31_0,
	MLX5_MODI_OUT_DIPV6_127_96,
	MLX5_MODI_OUT_DIPV6_95_64,
	MLX5_MODI_OUT_DIPV6_63_32,
	MLX5_MODI_OUT_DIPV6_31_0,
	MLX5_MODI_OUT_SIPV4,
	MLX5_MODI_OUT_DIPV4,
	MLX5_MODI_IN_SMAC_47_16 = 0x31,
	MLX5_MODI_IN_SMAC_15_0,
	MLX5_MODI_IN_ETHERTYPE,
	MLX5_MODI_IN_DMAC_47_16,
	MLX5_MODI_IN_DMAC_15_0,
	MLX5_MODI_IN_IP_DSCP,
	MLX5_MODI_IN_TCP_FLAGS,
	MLX5_MODI_IN_TCP_SPORT,
	MLX5_MODI_IN_TCP_DPORT,
	MLX5_MODI_IN_IPV4_TTL,
	MLX5_MODI_IN_UDP_SPORT,
	MLX5_MODI_IN_UDP_DPORT,
	MLX5_MODI_IN_SIPV6_127_96,
	MLX5_MODI_IN_SIPV6_95_64,
	MLX5_MODI_IN_SIPV6_63_32,
	MLX5_MODI_IN_SIPV6_31_0,
	MLX5_MODI_IN_DIPV6_127_96,
	MLX5_MODI_IN_DIPV6_95_64,
	MLX5_MODI_IN_DIPV6_63_32,
	MLX5_MODI_IN_DIPV6_31_0,
	MLX5_MODI_IN_SIPV4,
	MLX5_MODI_IN_DIPV4,
	MLX5_MODI_OUT_IPV6_HOPLIMIT,
	MLX5_MODI_IN_IPV6_HOPLIMIT,
	MLX5_MODI_META_DATA_REG_A,
	MLX5_MODI_META_DATA_REG_B = 0x50,
};

/* Modification sub command. */
struct mlx5_modification_cmd {
	union {
		uint32_t data0;
		struct {
			unsigned int bits:5;
			unsigned int rsvd0:3;
			unsigned int src_offset:5; /* Start bit offset. */
			unsigned int rsvd1:3;
			unsigned int src_field:12;
			unsigned int type:4;
		};
	};
	union {
		uint32_t data1;
		uint8_t data[4];
		struct {
			unsigned int rsvd2:8;
			unsigned int dst_offset:8;
			unsigned int dst_field:12;
			unsigned int rsvd3:4;
		};
	};
};

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define __mlx5_nullp(typ) ((struct mlx5_ifc_##typ##_bits *)0)
#define __mlx5_bit_sz(typ, fld) sizeof(__mlx5_nullp(typ)->fld)
#define __mlx5_bit_off(typ, fld) (offsetof(struct mlx5_ifc_##typ##_bits, fld))
#define __mlx5_dw_bit_off(typ, fld) (32 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0x1f))
#define __mlx5_dw_off(typ, fld) (__mlx5_bit_off(typ, fld) / 32)
#define __mlx5_64_off(typ, fld) (__mlx5_bit_off(typ, fld) / 64)
#define __mlx5_dw_mask(typ, fld) (__mlx5_mask(typ, fld) << \
				  __mlx5_dw_bit_off(typ, fld))
#define __mlx5_mask(typ, fld) ((u32)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_off(typ, fld) (__mlx5_bit_off(typ, fld) / 16)
#define __mlx5_16_bit_off(typ, fld) (16 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0xf))
#define __mlx5_mask16(typ, fld) ((u16)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_mask(typ, fld) (__mlx5_mask16(typ, fld) << \
				  __mlx5_16_bit_off(typ, fld))
#define MLX5_ST_SZ_DW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 32)
#define MLX5_ST_SZ_DB(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
#define MLX5_BYTE_OFF(typ, fld) (__mlx5_bit_off(typ, fld) / 8)
#define MLX5_ADDR_OF(typ, p, fld) ((char *)(p) + MLX5_BYTE_OFF(typ, fld))

/* insert a value to a struct */
#define MLX5_SET(typ, p, fld, v) \
	do { \
		u32 _v = v; \
		*((__be32 *)(p) + __mlx5_dw_off(typ, fld)) = \
		rte_cpu_to_be_32((rte_be_to_cpu_32(*((u32 *)(p) + \
				  __mlx5_dw_off(typ, fld))) & \
				  (~__mlx5_dw_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask(typ, fld)) << \
				   __mlx5_dw_bit_off(typ, fld))); \
	} while (0)
#define MLX5_SET16(typ, p, fld, v) \
	do { \
		u16 _v = v; \
		*((__be16 *)(p) + __mlx5_16_off(typ, fld)) = \
		rte_cpu_to_be_16((rte_be_to_cpu_16(*((__be16 *)(p) + \
				  __mlx5_16_off(typ, fld))) & \
				  (~__mlx5_16_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask16(typ, fld)) << \
				  __mlx5_16_bit_off(typ, fld))); \
	} while (0)
#define __MLX5_SET64(typ, p, fld, v) do { \
	assert(__mlx5_bit_sz(typ, fld) == 64); \
	*((__be64 *)(p) + __mlx5_64_off(typ, fld)) = rte_cpu_to_be_64(v); \
} while (0)
#define MLX5_SET64(typ, p, fld, v) do { \
	assert(__mlx5_bit_off(typ, fld) % 64 == 0); \
	__MLX5_SET64(typ, p, fld, v); \
} while (0)
#define MLX5_GET16(typ, p, fld) \
	((rte_be_to_cpu_16(*((__be16 *)(p) + \
	  __mlx5_16_off(typ, fld))) >> __mlx5_16_bit_off(typ, fld)) & \
	 __mlx5_mask16(typ, fld))
#define MLX5_FLD_SZ_BYTES(typ, fld) (__mlx5_bit_sz(typ, fld) / 8)
#define MLX5_GET(typ, p, fld) ((rte_be_to_cpu_32(*((__be32 *)(p) + \
		 __mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
		__mlx5_mask(typ, fld))
#define MLX5_GET64(typ, p, fld) (rte_be_to_cpu_64(*((__be64 *)(p) + \
		__mlx5_64_off(typ, fld))))

struct mlx5_cmd_block {
	u8     data[512];
	u8     rsvd0[48];
	__be64 next;
	__be32 block_num;
	u8     rsvd1;
	u8     token;
	u8     ctrl_sig;
	u8     sig;
};

struct mlx5_cmdq_entry {
	u8	type;
	u8	rsvd0[3];
	__be32	ilen;
	__be64	iptr;
	__be32	in[4];
	__be32	out[4];
	__be64	optr;
	__be32	olen;
	u8	token;
	u8	sig;
	u8	rsvd1;
	u8	status_own;
};

struct mlx5_iseg {
	__be16 fw_rev_minor;
	__be16 fw_rev_major;
	__be16 cmdif_rev;
	__be16 fw_rev_sub;
	__be32 rsvd0[2];
	__be32 cmdq_pa_h;
	__be32 cmdq_pa_l_sz;
	__be32 cmd_dbell;
	__be32 rsvd1[120];
	__be32 initializing;
	__be32 health[16];
	__be32 rsvd2[880];
	__be32 internal_timer_h;
	__be32 internal_timer_l;
	__be32 rsvd3[2];
	__be32 health_counter;
	__be32 rsvd4[1019];
	__be64 ieee1588_clk;
	__be32 ieee1588_clk_type;
	__be32 clr_intx;
};

struct mlx5_ifc_enable_hca_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x20];
};

struct mlx5_ifc_enable_hca_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x10];
	u8 function_id[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_disable_hca_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x20];
};

struct mlx5_ifc_disable_hca_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x10];
	u8 function_id[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_query_issi_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x10];
	u8 current_issi[0x10];
	u8 reserved_at_60[0xa0];
	u8 reserved_at_100[76][0x8];
	u8 supported_issi_dw0[0x20];
};

struct mlx5_ifc_query_issi_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_set_issi_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_set_issi_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x10];
	u8 current_issi[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_init_hca_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_init_hca_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_teardown_hca_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x3f];
	u8 force_state[0x1];
};

struct mlx5_ifc_teardown_hca_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x10];
	u8 profile[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_set_driver_version_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	u8 driver_version[0x200];
};

struct mlx5_ifc_set_driver_version_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_query_pages_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 embedded_cpu_function[0x01];
	u8 reserved_bits[0x0f];
	u8 function_id[0x10];
	u8 num_pages[0x20];
};

struct mlx5_ifc_query_pages_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x10];
	u8 function_id[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_manage_pages_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 output_num_entries[0x20];
	u8 reserved_at_60[0x20];
	__be64	pas[0];
};

struct mlx5_ifc_manage_pages_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 embedded_cpu_function[0x01];
	u8 reserved_bits[0x0f];
	u8 function_id[0x10];
	u8 input_num_entries[0x20];
	__be64 pas[0x20];
};

struct mlx5_ifc_create_uctx_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x10];
	u8 uid[0x10];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_uctx_bits {
	u8 cap[0x20];
	u8 reserved_at_20[0x160];
};

struct mlx5_ifc_create_uctx_in_bits {
	u8 opcode[0x10];
	u8 reserved_at_10[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	struct mlx5_ifc_uctx_bits uctx;
};

struct mlx5_ifc_fte_match_set_misc_bits {
	u8 reserved_at_0[0x8];
	u8 source_sqn[0x18];
	u8 reserved_at_20[0x10];
	u8 source_port[0x10];
	u8 outer_second_prio[0x3];
	u8 outer_second_cfi[0x1];
	u8 outer_second_vid[0xc];
	u8 inner_second_prio[0x3];
	u8 inner_second_cfi[0x1];
	u8 inner_second_vid[0xc];
	u8 outer_second_cvlan_tag[0x1];
	u8 inner_second_cvlan_tag[0x1];
	u8 outer_second_svlan_tag[0x1];
	u8 inner_second_svlan_tag[0x1];
	u8 reserved_at_64[0xc];
	u8 gre_protocol[0x10];
	u8 gre_key_h[0x18];
	u8 gre_key_l[0x8];
	u8 vxlan_vni[0x18];
	u8 reserved_at_b8[0x8];
	u8 reserved_at_c0[0x20];
	u8 reserved_at_e0[0xc];
	u8 outer_ipv6_flow_label[0x14];
	u8 reserved_at_100[0xc];
	u8 inner_ipv6_flow_label[0x14];
	u8 reserved_at_120[0xe0];
};

struct mlx5_ifc_ipv4_layout_bits {
	u8 reserved_at_0[0x60];
	u8 ipv4[0x20];
};

struct mlx5_ifc_ipv6_layout_bits {
	u8 ipv6[16][0x8];
};

union mlx5_ifc_ipv6_layout_ipv4_layout_auto_bits {
	struct mlx5_ifc_ipv6_layout_bits ipv6_layout;
	struct mlx5_ifc_ipv4_layout_bits ipv4_layout;
	u8 reserved_at_0[0x80];
};

struct mlx5_ifc_fte_match_set_lyr_2_4_bits {
	u8 smac_47_16[0x20];
	u8 smac_15_0[0x10];
	u8 ethertype[0x10];
	u8 dmac_47_16[0x20];
	u8 dmac_15_0[0x10];
	u8 first_prio[0x3];
	u8 first_cfi[0x1];
	u8 first_vid[0xc];
	u8 ip_protocol[0x8];
	u8 ip_dscp[0x6];
	u8 ip_ecn[0x2];
	u8 cvlan_tag[0x1];
	u8 svlan_tag[0x1];
	u8 frag[0x1];
	u8 ip_version[0x4];
	u8 tcp_flags[0x9];
	u8 tcp_sport[0x10];
	u8 tcp_dport[0x10];
	u8 reserved_at_c0[0x20];
	u8 udp_sport[0x10];
	u8 udp_dport[0x10];
	union mlx5_ifc_ipv6_layout_ipv4_layout_auto_bits src_ipv4_src_ipv6;
	union mlx5_ifc_ipv6_layout_ipv4_layout_auto_bits dst_ipv4_dst_ipv6;
};

struct mlx5_ifc_fte_match_mpls_bits {
	u8 mpls_label[0x14];
	u8 mpls_exp[0x3];
	u8 mpls_s_bos[0x1];
	u8 mpls_ttl[0x8];
};

struct mlx5_ifc_fte_match_set_misc2_bits {
	struct mlx5_ifc_fte_match_mpls_bits outer_first_mpls;
	struct mlx5_ifc_fte_match_mpls_bits inner_first_mpls;
	struct mlx5_ifc_fte_match_mpls_bits outer_first_mpls_over_gre;
	struct mlx5_ifc_fte_match_mpls_bits outer_first_mpls_over_udp;
	u8 reserved_at_80[0x100];
	u8 metadata_reg_a[0x20];
	u8 reserved_at_1a0[0x60];
};

/* Flow matcher. */
struct mlx5_ifc_fte_match_param_bits {
	struct mlx5_ifc_fte_match_set_lyr_2_4_bits outer_headers;
	struct mlx5_ifc_fte_match_set_misc_bits misc_parameters;
	struct mlx5_ifc_fte_match_set_lyr_2_4_bits inner_headers;
	struct mlx5_ifc_fte_match_set_misc2_bits misc_parameters_2;
	u8 reserved_at_800[0x800];
};

enum {
	MLX5_MATCH_CRITERIA_ENABLE_OUTER_BIT,
	MLX5_MATCH_CRITERIA_ENABLE_MISC_BIT,
	MLX5_MATCH_CRITERIA_ENABLE_INNER_BIT,
	MLX5_MATCH_CRITERIA_ENABLE_MISC2_BIT
};

enum {
	MLX5_CAP_PORT_TYPE_IB  = 0x0,
	MLX5_CAP_PORT_TYPE_ETH = 0x1,
};

struct mlx5_ifc_cmd_hca_cap_bits {
	u8 reserved_at_0[0x30];
	u8 vhca_id[0x10];

	u8 reserved_at_40[0x40];

	u8 log_max_srq_sz[0x8];
	u8 log_max_qp_sz[0x8];
	u8 reserved_at_90[0xb];
	u8 log_max_qp[0x5];

	u8 reserved_at_a0[0xb];
	u8 log_max_srq[0x5];
	u8 reserved_at_b0[0x10];

	u8 reserved_at_c0[0x8];
	u8 log_max_cq_sz[0x8];
	u8 reserved_at_d0[0xb];
	u8 log_max_cq[0x5];

	u8 log_max_eq_sz[0x8];
	u8 reserved_at_e8[0x2];
	u8 log_max_mkey[0x6];
	u8 reserved_at_f0[0x8];
	u8 dump_fill_mkey[0x1];
	u8 reserved_at_f9[0x2];
	u8 fast_teardown[0x1];
	u8 log_max_eq[0x4];

	u8 max_indirection[0x8];
	u8 fixed_buffer_size[0x1];
	u8 log_max_mrw_sz[0x7];
	u8 force_teardown[0x1];
	u8 reserved_at_111[0x1];
	u8 log_max_bsf_list_size[0x6];
	u8 umr_extended_translation_offset[0x1];
	u8 null_mkey[0x1];
	u8 log_max_klm_list_size[0x6];

	u8 reserved_at_120[0xa];
	u8 log_max_ra_req_dc[0x6];
	u8 reserved_at_130[0xa];
	u8 log_max_ra_res_dc[0x6];

	u8 reserved_at_140[0xa];
	u8 log_max_ra_req_qp[0x6];
	u8 reserved_at_150[0xa];
	u8 log_max_ra_res_qp[0x6];

	u8 end_pad[0x1];
	u8 cc_query_allowed[0x1];
	u8 cc_modify_allowed[0x1];
	u8 start_pad[0x1];
	u8 cache_line_128byte[0x1];
	u8 reserved_at_165[0xa];
	u8 qcam_reg[0x1];
	u8 gid_table_size[0x10];

	u8 out_of_seq_cnt[0x1];
	u8 vport_counters[0x1];
	u8 retransmission_q_counters[0x1];
	u8 debug[0x1];
	u8 modify_rq_counter_set_id[0x1];
	u8 rq_delay_drop[0x1];
	u8 max_qp_cnt[0xa];
	u8 pkey_table_size[0x10];

	u8 vport_group_manager[0x1];
	u8 vhca_group_manager[0x1];
	u8 ib_virt[0x1];
	u8 eth_virt[0x1];
	u8 vnic_env_queue_counters[0x1];
	u8 ets[0x1];
	u8 nic_flow_table[0x1];
	u8 eswitch_manager[0x1];
	u8 device_memory[0x1];
	u8 mcam_reg[0x1];
	u8 pcam_reg[0x1];
	u8 local_ca_ack_delay[0x5];
	u8 port_module_event[0x1];
	u8 enhanced_error_q_counters[0x1];
	u8 ports_check[0x1];
	u8 reserved_at_1b3[0x1];
	u8 disable_link_up[0x1];
	u8 beacon_led[0x1];
	u8 port_type[0x2];
	u8 num_ports[0x8];

	u8 reserved_at_1c0[0x1];
	u8 pps[0x1];
	u8 pps_modify[0x1];
	u8 log_max_msg[0x5];
	u8 reserved_at_1c8[0x4];
	u8 max_tc[0x4];
	u8 temp_warn_event[0x1];
	u8 dcbx[0x1];
	u8 general_notification_event[0x1];
	u8 reserved_at_1d3[0x2];
	u8 fpga[0x1];
	u8 rol_s[0x1];
	u8 rol_g[0x1];
	u8 reserved_at_1d8[0x1];
	u8 wol_s[0x1];
	u8 wol_g[0x1];
	u8 wol_a[0x1];
	u8 wol_b[0x1];
	u8 wol_m[0x1];
	u8 wol_u[0x1];
	u8 wol_p[0x1];

	u8 stat_rate_support[0x10];
	u8 reserved_at_1f0[0xc];
	u8 cqe_version[0x4];

	u8 compact_address_vector[0x1];
	u8 striding_rq[0x1];
	u8 reserved_at_202[0x1];
	u8 ipoib_enhanced_offloads[0x1];
	u8 ipoib_basic_offloads[0x1];
	u8 reserved_at_205[0x1];
	u8 repeated_block_disabled[0x1];
	u8 umr_modify_entity_size_disabled[0x1];
	u8 umr_modify_atomic_disabled[0x1];
	u8 umr_indirect_mkey_disabled[0x1];
	u8 umr_fence[0x2];
	u8 dc_req_scat_data_cqe[0x1];
	u8 reserved_at_20d[0x2];
	u8 drain_sigerr[0x1];
	u8 cmdif_checksum[0x2];
	u8 sigerr_cqe[0x1];
	u8 reserved_at_213[0x1];
	u8 wq_signature[0x1];
	u8 sctr_data_cqe[0x1];
	u8 reserved_at_216[0x1];
	u8 sho[0x1];
	u8 tph[0x1];
	u8 rf[0x1];
	u8 dct[0x1];
	u8 qos[0x1];
	u8 eth_net_offloads[0x1];
	u8 roce[0x1];
	u8 atomic[0x1];
	u8 reserved_at_21f[0x1];

	u8 cq_oi[0x1];
	u8 cq_resize[0x1];
	u8 cq_moderation[0x1];
	u8 reserved_at_223[0x3];
	u8 cq_eq_remap[0x1];
	u8 pg[0x1];
	u8 block_lb_mc[0x1];
	u8 reserved_at_229[0x1];
	u8 scqe_break_moderation[0x1];
	u8 cq_period_start_from_cqe[0x1];
	u8 cd[0x1];
	u8 reserved_at_22d[0x1];
	u8 apm[0x1];
	u8 vector_calc[0x1];
	u8 umr_ptr_rlky[0x1];
	u8 imaicl[0x1];
	u8 reserved_at_232[0x4];
	u8 qkv[0x1];
	u8 pkv[0x1];
	u8 set_deth_sqpn[0x1];
	u8 reserved_at_239[0x3];
	u8 xrc[0x1];
	u8 ud[0x1];
	u8 uc[0x1];
	u8 rc[0x1];

	u8 uar_4k[0x1];
	u8 reserved_at_241[0x9];
	u8 uar_sz[0x6];
	u8 reserved_at_250[0x8];
	u8 log_pg_sz[0x8];

	u8 bf[0x1];
	u8 driver_version[0x1];
	u8 pad_tx_eth_packet[0x1];
	u8 reserved_at_263[0x8];
	u8 log_bf_reg_size[0x5];

	u8 reserved_at_270[0xb];
	u8 lag_master[0x1];
	u8 num_lag_ports[0x4];

	u8 reserved_at_280[0x10];
	u8 max_wqe_sz_sq[0x10];

	u8 reserved_at_2a0[0x10];
	u8 max_wqe_sz_rq[0x10];

	u8 max_flow_counter_31_16[0x10];
	u8 max_wqe_sz_sq_dc[0x10];

	u8 reserved_at_2e0[0x7];
	u8 max_qp_mcg[0x19];

	u8 reserved_at_300[0x18];
	u8 log_max_mcg[0x8];

	u8 reserved_at_320[0x3];
	u8 log_max_transport_domain[0x5];
	u8 reserved_at_328[0x3];
	u8 log_max_pd[0x5];
	u8 reserved_at_330[0xb];
	u8 log_max_xrcd[0x5];

	u8 nic_receive_steering_discard[0x1];
	u8 receive_discard_vport_down[0x1];
	u8 transmit_discard_vport_down[0x1];
	u8 reserved_at_343[0x5];
	u8 log_max_flow_counter_bulk[0x8];
	u8 max_flow_counter_15_0[0x10];


	u8 reserved_at_360[0x3];
	u8 log_max_rq[0x5];
	u8 reserved_at_368[0x3];
	u8 log_max_sq[0x5];
	u8 reserved_at_370[0x3];
	u8 log_max_tir[0x5];
	u8 reserved_at_378[0x3];
	u8 log_max_tis[0x5];

	u8 basic_cyclic_rcv_wqe[0x1];
	u8 reserved_at_381[0x2];
	u8 log_max_rmp[0x5];
	u8 reserved_at_388[0x3];
	u8 log_max_rqt[0x5];
	u8 reserved_at_390[0x3];
	u8 log_max_rqt_size[0x5];
	u8 reserved_at_398[0x3];
	u8 log_max_tis_per_sq[0x5];

	u8 ext_stride_num_range[0x1];
	u8 reserved_at_3a1[0x2];
	u8 log_max_stride_sz_rq[0x5];
	u8 reserved_at_3a8[0x3];
	u8 log_min_stride_sz_rq[0x5];
	u8 reserved_at_3b0[0x3];
	u8 log_max_stride_sz_sq[0x5];
	u8 reserved_at_3b8[0x3];
	u8 log_min_stride_sz_sq[0x5];

	u8 hairpin[0x1];
	u8 reserved_at_3c1[0x2];
	u8 log_max_hairpin_queues[0x5];
	u8 reserved_at_3c8[0x3];
	u8 log_max_hairpin_wq_data_sz[0x5];
	u8 reserved_at_3d0[0x3];
	u8 log_max_hairpin_num_packets[0x5];
	u8 reserved_at_3d8[0x3];
	u8 log_max_wq_sz[0x5];

	u8 nic_vport_change_event[0x1];
	u8 disable_local_lb_uc[0x1];
	u8 disable_local_lb_mc[0x1];
	u8 log_min_hairpin_wq_data_sz[0x5];
	u8 reserved_at_3e8[0x3];
	u8 log_max_vlan_list[0x5];
	u8 reserved_at_3f0[0x3];
	u8 log_max_current_mc_list[0x5];
	u8 reserved_at_3f8[0x3];
	u8 log_max_current_uc_list[0x5];

	u8 general_obj_types[0x40];

	u8 reserved_at_440[0x20];

	u8 reserved_at_460[0x10];
	u8 max_num_eqs[0x10];

	u8 reserved_at_480[0x3];
	u8 log_max_l2_table[0x5];
	u8 reserved_at_488[0x8];
	u8 log_uar_page_sz[0x10];

	u8 reserved_at_4a0[0x20];
	u8 device_frequency_mhz[0x20];
	u8 device_frequency_khz[0x20];

	u8 reserved_at_500[0x20];
	u8 num_of_uars_per_page[0x20];

	u8 flex_parser_protocols[0x20];
	u8 reserved_at_560[0x20];

	u8 reserved_at_580[0x3c];
	u8 mini_cqe_resp_stride_index[0x1];
	u8 cqe_128_always[0x1];
	u8 cqe_compression_128[0x1];
	u8 cqe_compression[0x1];

	u8 cqe_compression_timeout[0x10];
	u8 cqe_compression_max_num[0x10];

	u8 reserved_at_5e0[0x10];
	u8 tag_matching[0x1];
	u8 rndv_offload_rc[0x1];
	u8 rndv_offload_dc[0x1];
	u8 log_tag_matching_list_sz[0x5];
	u8 reserved_at_5f8[0x3];
	u8 log_max_xrq[0x5];

	u8 affiliate_nic_vport_criteria[0x8];
	u8 native_port_num[0x8];
	u8 num_vhca_ports[0x8];
	u8 reserved_at_618[0x6];
	u8 sw_owner_id[0x1];
	u8 reserved_at_61f[0x1e1];
};

struct mlx5_ifc_virtio_net_cap_bits {
	u8 reserved_at_0[0x18];
	u8 virtio_queue_type[0x8];
	u8 reserved_at_20[0x13];
	u8 log_doorbell_stride[0x5];
	u8 reserved_at_38[0x3];
	u8 log_doorbell_bar_size[0x5];
	u8 doorbell_bar_offset[0x40];
	u8 reserved_at_80[0x8];
	u8 max_num_virtio_queues[0x18];
	u8 reserved_at_a0[0x760];
};

struct mlx5_ifc_per_protocol_networking_offload_caps_bits {
	u8 csum_cap[0x1];
	u8 vlan_cap[0x1];
	u8 lro_cap[0x1];
	u8 lro_psh_flag[0x1];
	u8 lro_time_stamp[0x1];
	u8 reserved_at_5[0x2];
	u8 wqe_vlan_insert[0x1];
	u8 self_lb_en_modifiable[0x1];
	u8 self_lb_mc[0x1];
	u8 self_lb_uc[0x1];
	u8 max_lso_cap[0x5];
	u8 multi_pkt_send_wqe[0x2];
	u8 wqe_inline_mode[0x2];
	u8 rss_ind_tbl_cap[0x4];
	u8 reg_umr_sq[0x1];
	u8 scatter_fcs[0x1];
	u8 enhanced_multi_pkt_send_wqe[0x1];
	u8 tunnel_lso_const_out_ip_id[0x1];
	u8 reserved_at_1c[0x2];
	u8 tunnel_stateless_gre[0x1];
	u8 tunnel_stateless_vxlan[0x1];
	u8 swp[0x1];
	u8 swp_csum[0x1];
	u8 swp_lso[0x1];
	u8 reserved_at_23[0x1d];
	u8 reserved_at_40[0x10];
	u8 lro_min_mss_size[0x10];
	u8 reserved_at_60[0x120];
	u8 lro_timer_supported_periods[4][0x20];
	u8 reserved_at_200[0x600];
};

struct mlx5_ifc_flow_table_fields_supported_bits {
	u8 outer_dmac[0x1];
	u8 outer_smac[0x1];
	u8 outer_ether_type[0x1];
	u8 outer_ip_version[0x1];
	u8 outer_first_prio[0x1];
	u8 outer_first_cfi[0x1];
	u8 outer_first_vid[0x1];
	u8 outer_ipv4_ttl[0x1];
	u8 outer_second_prio[0x1];
	u8 outer_second_cfi[0x1];
	u8 outer_second_vid[0x1];
	u8 reserved_at_b[0x1];
	u8 outer_sip[0x1];
	u8 outer_dip[0x1];
	u8 outer_frag[0x1];
	u8 outer_ip_protocol[0x1];
	u8 outer_ip_ecn[0x1];
	u8 outer_ip_dscp[0x1];
	u8 outer_udp_sport[0x1];
	u8 outer_udp_dport[0x1];
	u8 outer_tcp_sport[0x1];
	u8 outer_tcp_dport[0x1];
	u8 outer_tcp_flags[0x1];
	u8 outer_gre_protocol[0x1];
	u8 outer_gre_key[0x1];
	u8 outer_vxlan_vni[0x1];
	u8 reserved_at_1a[0x5];
	u8 source_eswitch_port[0x1];
	u8 inner_dmac[0x1];
	u8 inner_smac[0x1];
	u8 inner_ether_type[0x1];
	u8 inner_ip_version[0x1];
	u8 inner_first_prio[0x1];
	u8 inner_first_cfi[0x1];
	u8 inner_first_vid[0x1];
	u8 inner_ipv4_ttl[0x1];
	u8 inner_second_prio[0x1];
	u8 inner_second_cfi[0x1];
	u8 inner_second_vid[0x1];
	u8 reserved_at_2b[0x1];
	u8 inner_sip[0x1];
	u8 inner_dip[0x1];
	u8 inner_frag[0x1];
	u8 inner_ip_protocol[0x1];
	u8 inner_ip_ecn[0x1];
	u8 inner_ip_dscp[0x1];
	u8 inner_udp_sport[0x1];
	u8 inner_udp_dport[0x1];
	u8 inner_tcp_sport[0x1];
	u8 inner_tcp_dport[0x1];
	u8 inner_tcp_flags[0x1];
	u8 reserved_at_37[0x9];
	u8 reserved_at_40[0x1a];
	u8 bth_dst_qp[0x1];
	u8 reserved_at_5b[0x25];
};

struct mlx5_ifc_flow_table_prop_layout_bits {
	u8 ft_support[0x1];
	u8 reserved_at_1[0x1];
	u8 flow_counter[0x1];
	u8 flow_modify_en[0x1];
	u8 modify_root[0x1];
	u8 identified_miss_table_mode[0x1];
	u8 flow_table_modify[0x1];
	u8 encap[0x1];
	u8 decap[0x1];
	u8 reserved_at_9[0x17];
	u8 reserved_at_20[0x2];
	u8 log_max_ft_size[0x6];
	u8 log_max_modify_header_context[0x8];
	u8 max_modify_header_actions[0x8];
	u8 max_ft_level[0x8];
	u8 reserved_at_40[0x20];
	u8 reserved_at_60[0x18];
	u8 log_max_ft_num[0x8];
	u8 reserved_at_80[0x18];
	u8 log_max_destination[0x8];
	u8 reserved_at_a0[0x18];
	u8 log_max_flow[0x8];
	u8 reserved_at_c0[0x40];
	struct mlx5_ifc_flow_table_fields_supported_bits ft_field_support;
	struct mlx5_ifc_flow_table_fields_supported_bits ft_field_bitmask_support;
};

struct mlx5_ifc_flow_table_nic_cap_bits {
	u8 nic_rx_multi_path_tirs[0x1];
	u8 nic_rx_multi_path_tirs_fts[0x1];
	u8 allow_sniffer_and_nic_rx_shared_tir[0x1];
	u8 reserved_at_3[0x1fd];
	struct mlx5_ifc_flow_table_prop_layout_bits nic_rx;
	u8 reserved_at_400[0x200];
	struct mlx5_ifc_flow_table_prop_layout_bits nic_rx_sniffer;
	struct mlx5_ifc_flow_table_prop_layout_bits nic_tx;
	u8 reserved_at_a00[0x200];
	struct mlx5_ifc_flow_table_prop_layout_bits nic_tx_sniffer;
	u8 reserved_at_e00[0x7200];
};

union mlx5_ifc_hca_cap_union_bits {
	struct mlx5_ifc_cmd_hca_cap_bits cmd_hca_cap;
	struct mlx5_ifc_per_protocol_networking_offload_caps_bits per_protocol_networking_offload_caps;
	struct mlx5_ifc_flow_table_nic_cap_bits flow_table_nic_cap;
	struct mlx5_ifc_virtio_net_cap_bits virtio_net_cap;
	u8 reserved_at_0[0x8000];
};

struct mlx5_ifc_query_hca_cap_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_query_hca_cap_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
	union mlx5_ifc_hca_cap_union_bits capability;
};

struct mlx5_ifc_query_special_contexts_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_query_special_contexts_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 dump_fill_mkey[0x20];
	u8 resd_lkey[0x20];
	u8 null_mkey[0x20];
	u8 reserved_at_a0[0x60];
};

struct mlx5_ifc_rx_hash_field_select_bits {
	u8 l3_prot_type[0x1];
	u8 l4_prot_type[0x1];
	u8 selected_fields[0x1e];
};

struct mlx5_ifc_tirc_bits {
	u8 reserved_at_0[0x20];
	u8 disp_type[0x4];
	u8 reserved_at_24[0x60];
	u8 lro_timeout_period_usecs[0x10];
	u8 lro_enable_mask[0x4];
	u8 lro_max_ip_payload_size[0x8];
	u8 reserved_at_a0[0x45];
	u8 inline_q_type[0x3];
	u8 inline_rqn[0x18];
	u8 rx_hash_symmetric[0x1];
	u8 reserved_at_101[0x1];
	u8 tunneled_offload_en[0x1];
	u8 reserved_at_103[0x5];
	u8 indirect_table[0x18];
	u8 rx_hash_fn[0x4];
	u8 reserved_at_124[0x2];
	u8 self_lb_block[0x2];
	u8 transport_domain[0x18];
	u8 rx_hash_toeplitz_key[10][0x20];
	struct mlx5_ifc_rx_hash_field_select_bits rx_hash_field_selector_outer;
	struct mlx5_ifc_rx_hash_field_select_bits rx_hash_field_selector_inner;
	u8 reserved_at_2c0[0x4c0];
};

struct mlx5_ifc_create_tir_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0xc0];
	struct mlx5_ifc_tirc_bits ctx;
};

struct mlx5_ifc_create_tir_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 tirn[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_rq_num_bits {
	u8 reserved_at_0[0x8];
	u8 rq_num[0x18];
};

struct mlx5_ifc_rqtc_bits {
	u8 reserved_at_0[0xa5];
	u8 list_q_type[0x3];
	u8 reserved_at_a8[0x8];
	u8 rqt_max_size[0x10];
	u8 reserved_at_c0[0x10];
	u8 rqt_actual_size[0x10];
	u8 reserved_at_e0[0x6a0];
	struct mlx5_ifc_rq_num_bits rq_num[0];
};

struct mlx5_ifc_create_rqt_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0xc0];
	struct mlx5_ifc_rqtc_bits rqt_context;
};

struct mlx5_ifc_create_rqt_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 rqtn[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_alloc_pd_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_alloc_pd_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 pd[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_mtt_entry_bits {
	u8 ptag[0x38];
	u8 reserved_at_38[0x6];
	u8 wr_en[0x1];
	u8 rd_en[0x1];
};

struct mlx5_ifc_umemc_bits {
	u8 reserved_at_0[0x9b];
	u8 log_page_size[0x5];
	u8 page_offset[0x20];
	u8 num_of_mtt[0x40];
	struct mlx5_ifc_mtt_entry_bits mtt[1];
};

struct mlx5_ifc_create_umem_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	struct mlx5_ifc_umemc_bits umem_context;
};

struct mlx5_ifc_create_umem_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 umem_id[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_general_obj_in_cmd_hdr_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 obj_type[0x10];
	u8 obj_id[0x20];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_general_obj_out_cmd_hdr_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 obj_id[0x20];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_virtq_bits {
	u8 modify_field_select[0x40];
	u8 reserved_at_40[0x40];
	u8 virtio_q_type[0x8];
	u8 tisn[0x18];
	u8 virtio_q_state[0x4];
	u8 virtio_direction[0x4];
	u8 reserved_at_a8[0x18];
	u8 desc_addr[0x40];
	u8 used_addr[0x40];
	u8 available_addr[0x40];
	u8 ctrl_mkey[0x20];
	u8 data_mkey[0x20];
	u8 umem_offset[0x40];
	u8 umem_id[0x20];
	u8 doorbell_stride_idx[0x10];
	u8 queue_size[0x10];
	u8 reserved_at_240[0x5c0];
};

struct mlx5_ifc_create_virtq_in_bits {
	struct mlx5_ifc_general_obj_in_cmd_hdr_bits hdr;
	struct mlx5_ifc_virtq_bits virtq;
};

struct mlx5_ifc_flow_table_context_bits {
	u8 reformat_en[0x1];
	u8 decap_en[0x1];
	u8 sw_owner[0x1];
	u8 termination_table[0x1];
	u8 table_miss_action[0x4];
	u8 level[0x8];
	u8 reserved_at_10[0x8];
	u8 log_size[0x8];
	u8 reserved_at_20[0x8];
	u8 table_miss_id[0x18];
	u8 reserved_at_40[0x100];
};

struct mlx5_ifc_create_flow_table_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	u8 table_type[0x8];
	u8 reserved_at_88[0x38];
	struct mlx5_ifc_flow_table_context_bits ftc;
};

struct mlx5_ifc_create_flow_table_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 table_id[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_set_flow_table_root_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	u8 table_type[0x8];
	u8 reserved_at_88[0x20];
	u8 table_id[0x18];
	u8 reserved_at_c0[0x140];
};

struct mlx5_ifc_set_flow_table_root_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_create_flow_group_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	u8 table_type[0x8];
	u8 reserved_at_88[0x20];
	u8 table_id[0x18];
	u8 reserved_at_c0[0x20];
	u8 start_flow_index[0x20];
	u8 reserved_at_100[0x20];
	u8 end_flow_index[0x20];
	u8 reserved_at_140[0xb8];
	u8 match_criteria_enable[0x8];
	struct mlx5_ifc_fte_match_param_bits match_criteria;
	u8 reserved_at_1200[0xe00];
};

struct mlx5_ifc_create_flow_group_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x8];
	u8 group_id[0x18];
	u8 reserved_at_60[0x20];
};

struct mlx5_ifc_vlan_bits {
	u8 ethtype[0x10];
	u8 prio[0x3];
	u8 cfi[0x1];
	u8 vid[0xc];
};

struct mlx5_ifc_dest_format_struct_bits {
	u8 destination_type[0x8];
	u8 destination_id[0x18];
	u8 destination_eswitch_owner_vhca_id_valid[0x1];
	u8 packet_reformat[0x1];
	u8 reserved_at_22[0xe];
	u8 destination_eswitch_owner_vhca_id[0x10];
};

struct mlx5_ifc_flow_counter_list_bits {
	u8 flow_counter_id[0x20];
	u8 reserved_at_20[0x20];
};

union mlx5_ifc_basic_dest_counter_list_bits {
	struct mlx5_ifc_dest_format_struct_bits dest_format_struct;
	struct mlx5_ifc_flow_counter_list_bits flow_counter_list;
	u8 reserved_at_0[0x40];
};

struct mlx5_ifc_flow_context_bits {
	struct mlx5_ifc_vlan_bits push_vlan;
	u8 group_id[0x20];
	u8 reserved_at_40[0x8];
	u8 flow_tag[0x18];
	u8 reserved_at_60[0x10];
	u8 action[0x10];
	u8 extended_destination[0x1];
	u8 reserved_at_80[0x7];
	u8 destination_list_size[0x18];
	u8 reserved_at_a0[0x8];
	u8 flow_counter_list_size[0x18];
	u8 packet_reformat_id[0x20];
	u8 modify_header_id[0x20];
	struct mlx5_ifc_vlan_bits push_vlan_2;
	u8 reserved_at_120[0xe0];
	struct mlx5_ifc_fte_match_param_bits match_value;
	u8 reserved_at_1200[0x600];
	union mlx5_ifc_basic_dest_counter_list_bits destination[0];
};

struct mlx5_ifc_set_fte_in_bits {
	u8 opcode[0x10];
	u8 uid[0x10];
	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];
	u8 reserved_at_40[0x40];
	u8 table_type[0x8];
	u8 reserved_at_88[0x20];
	u8 table_id[0x18];
	u8 reserved_at_c0[0x40];
	u8 flow_index[0x20];
	u8 reserved_at_120[0xe0];
	struct mlx5_ifc_flow_context_bits flowc;
};

struct mlx5_ifc_set_fte_out_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];
	u8 syndrome[0x20];
	u8 reserved_at_40[0x40];
};

enum {
	MLX5_CMD_OP_QUERY_HCA_CAP          = 0x100,
	MLX5_CMD_OP_INIT_HCA               = 0x102,
	MLX5_CMD_OP_TEARDOWN_HCA           = 0x103,
	MLX5_CMD_OP_ENABLE_HCA             = 0x104,
	MLX5_CMD_OP_DISABLE_HCA            = 0x105,
	MLX5_CMD_OP_QUERY_PAGES		   = 0x107,
	MLX5_CMD_OP_MANAGE_PAGES	   = 0x108,
	MLX5_CMD_OP_QUERY_ISSI             = 0x10a,
	MLX5_CMD_OP_SET_ISSI               = 0x10b,
	MLX5_CMD_OP_SET_DRIVER_VERSION     = 0x10d,
	MLX5_CMD_OP_CREATE_MKEY            = 0x200,
	MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS = 0x203,
	MLX5_CMD_OP_ALLOC_PD               = 0x800,
	MLX5_CMD_OP_CREATE_TIR             = 0x900,
	MLX5_CMD_OP_CREATE_TIS             = 0x912,
	MLX5_CMD_OP_CREATE_RQT             = 0x916,
	MLX5_CMD_OP_SET_FLOW_TABLE_ROOT    = 0x92f,
	MLX5_CMD_OP_CREATE_FLOW_TABLE      = 0x930,
	MLX5_CMD_OP_CREATE_FLOW_GROUP      = 0x933,
	MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY   = 0x936,
	MLX5_CMD_OP_CREATE_GENERAL_OBJECT  = 0xa00,
	MLX5_CMD_OP_CREATE_UCTX            = 0xa04,
	MLX5_CMD_OP_CREATE_UMEM            = 0xa08,
};

enum {
	MLX5_HCA_CAP_GENERAL           = 0,
	MLX5_HCA_CAP_ETHERNET_OFFLOADS = 0x1,
	MLX5_HCA_CAP_FLOW_TABLE        = 0x7,
	MLX5_HCA_CAP_DEVICE_EMULATION  = 0x13,
};

enum {
	MLX5_HCA_CAP_OPMOD_GET_CUR = 1,
};

enum {
	MLX5_GENERAL_OBJ_TYPES_CAP_VIRTQ = (1ULL << 13),
};

enum {
	MLX5_OBJ_TYPE_VIRTQ = 0x000d,
};

enum {
	MLX5_UCTX_CAP_RAW_TX = 1UL << 0,
};

enum {
	MLX5_VIRTQ_OBJ_QUEUE_TYPE_RX = 0,
	MLX5_VIRTQ_OBJ_QUEUE_TYPE_TX = 1,
};

enum {
	MLX5_TIRC_DISP_TYPE_DIRECT   = 0x0,
	MLX5_TIRC_DISP_TYPE_INDIRECT = 0x1,
};

enum {
	MLX5_INLINE_Q_TYPE_RQ    = 0x0,
	MLX5_INLINE_Q_TYPE_VIRTQ = 0x1,
};

enum {
	MLX5_RX_HASH_FN_NONE           = 0x0,
	MLX5_RX_HASH_FN_INVERTED_XOR8  = 0x1,
	MLX5_RX_HASH_FN_TOEPLITZ       = 0x2,
};

enum {
	MLX5_L3_PROT_TYPE_IPV4          = 0,
	MLX5_L3_PROT_TYPE_IPV6          = 1,
};

enum {
	MLX5_L4_PROT_TYPE_TCP           = 0,
	MLX5_L4_PROT_TYPE_UDP           = 1,
};

enum {
	MLX5_HASH_FIELD_SEL_SRC_IP	= 1 << 0,
	MLX5_HASH_FIELD_SEL_DST_IP	= 1 << 1,
	MLX5_HASH_FIELD_SEL_L4_SPORT	= 1 << 2,
	MLX5_HASH_FIELD_SEL_L4_DPORT	= 1 << 3,
	MLX5_HASH_FIELD_SEL_IPSEC_SPI	= 1 << 4,
};

enum {
	MLX5_FLOW_TABLE_TYPE_NIC_RX 		 = 0x0,
	MLX5_FLOW_TABLE_TYPE_NIC_TX 		 = 0x1,
	MLX5_FLOW_TABLE_TYPE_ESWITCH_EGRESS_ACL  = 0x2,
	MLX5_FLOW_TABLE_TYPE_ESWITCH_INGRESS_ACL = 0x3,
	MLX5_FLOW_TABLE_TYPE_ESWITCH_FDB 	 = 0x4,
	MLX5_FLOW_TABLE_TYPE_NIC_SNIFFER_RX 	 = 0x5,
	MLX5_FLOW_TABLE_TYPE_NIC_SNIFFER_TX 	 = 0x6,
	MLX5_FLOW_TABLE_TYPE_NIC_RX_RDMA 	 = 0x7,
	MLX5_FLOW_TABLE_TYPE_NIC_TX_RDMA 	 = 0x8,
};

enum {
	MLX5_FLOW_DESTINATION_TYPE_VPORT          = 0x0,
	MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE     = 0x1,
	MLX5_FLOW_DESTINATION_TYPE_TIR            = 0x2,
	MLX5_FLOW_DESTINATION_TYPE_PORT           = 0x99,
	MLX5_FLOW_DESTINATION_TYPE_COUNTER        = 0x100,
	MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM = 0x101,
};

enum {
	MLX5_FLOW_CONTEXT_ACTION_ALLOW           = 0x1,
	MLX5_FLOW_CONTEXT_ACTION_DROP      	 = 0x2,
	MLX5_FLOW_CONTEXT_ACTION_FWD_DEST  	 = 0x4,
	MLX5_FLOW_CONTEXT_ACTION_COUNT     	 = 0x8,
	MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT = 0x10,
	MLX5_FLOW_CONTEXT_ACTION_DECAP     	 = 0x20,
	MLX5_FLOW_CONTEXT_ACTION_MOD_HDR   	 = 0x40,
	MLX5_FLOW_CONTEXT_ACTION_VLAN_POP  	 = 0x80,
	MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH 	 = 0x100,
	MLX5_FLOW_CONTEXT_ACTION_VLAN_POP_2  	 = 0x400,
	MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH_2 	 = 0x800,
};

/* CQE format mask. */
#define MLX5E_CQE_FORMAT_MASK 0xc

/* MPW opcode. */
#define MLX5_OPC_MOD_MPW 0x01

/* Compressed Rx CQE structure. */
struct mlx5_mini_cqe8 {
	union {
		uint32_t rx_hash_result;
		struct {
			uint16_t checksum;
			uint16_t stride_idx;
		};
		struct {
			uint16_t wqe_counter;
			uint8_t  s_wqe_opcode;
			uint8_t  reserved;
		} s_wqe_info;
	};
	uint32_t byte_cnt;
};

/**
 * Convert a user mark to flow mark.
 *
 * @param val
 *   Mark value to convert.
 *
 * @return
 *   Converted mark value.
 */
static inline uint32_t
mlx5_flow_mark_set(uint32_t val)
{
	uint32_t ret;

	/*
	 * Add one to the user value to differentiate un-marked flows from
	 * marked flows, if the ID is equal to MLX5_FLOW_MARK_DEFAULT it
	 * remains untouched.
	 */
	if (val != MLX5_FLOW_MARK_DEFAULT)
		++val;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	/*
	 * Mark is 24 bits (minus reserved values) but is stored on a 32 bit
	 * word, byte-swapped by the kernel on little-endian systems. In this
	 * case, left-shifting the resulting big-endian value ensures the
	 * least significant 24 bits are retained when converting it back.
	 */
	ret = rte_cpu_to_be_32(val) >> 8;
#else
	ret = val;
#endif
	return ret;
}

/**
 * Convert a mark to user mark.
 *
 * @param val
 *   Mark value to convert.
 *
 * @return
 *   Converted mark value.
 */
static inline uint32_t
mlx5_flow_mark_get(uint32_t val)
{
	/*
	 * Subtract one from the retrieved value. It was added by
	 * mlx5_flow_mark_set() to distinguish unmarked flows.
	 */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	return (val >> 8) - 1;
#else
	return val - 1;
#endif
}

enum {
	MLX5_MKC_ACCESS_MODE_PA    = 0x0,
	MLX5_MKC_ACCESS_MODE_MTT   = 0x1,
	MLX5_MKC_ACCESS_MODE_KLMS  = 0x2,
	MLX5_MKC_ACCESS_MODE_KSM   = 0x3,
	MLX5_MKC_ACCESS_MODE_MEMIC = 0x5,
};

struct mlx5_ifc_klm_bits {
	u8         byte_count[0x20];
	u8         mkey[0x20];
	u8         address[0x40];
};

struct mlx5_ifc_mkc_bits {
	u8         reserved_at_0[0x1];
	u8         free[0x1];
	u8         reserved_at_2[0x1];
	u8         access_mode_4_2[0x3];
	u8         reserved_at_6[0x7];
	u8         relaxed_ordering_write[0x1];
	u8         reserved_at_e[0x1];
	u8         small_fence_on_rdma_read_response[0x1];
	u8         umr_en[0x1];
	u8         a[0x1];
	u8         rw[0x1];
	u8         rr[0x1];
	u8         lw[0x1];
	u8         lr[0x1];
	u8         access_mode_1_0[0x2];
	u8         reserved_at_18[0x8];
	u8         qpn[0x18];
	u8         mkey_7_0[0x8];
	u8         reserved_at_40[0x20];
	u8         length64[0x1];
	u8         bsf_en[0x1];
	u8         sync_umr[0x1];
	u8         reserved_at_63[0x2];
	u8         expected_sigerr_count[0x1];
	u8         reserved_at_66[0x1];
	u8         en_rinval[0x1];
	u8         pd[0x18];
	u8         start_addr[0x40];
	u8         len[0x40];
	u8         bsf_octword_size[0x20];
	u8         reserved_at_120[0x80];
	u8         translations_octword_size[0x20];
	u8         reserved_at_1c0[0x1b];
	u8         log_page_size[0x5];
	u8         reserved_at_1e0[0x20];
};

struct mlx5_ifc_create_mkey_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         reserved_at_40[0x8];
	u8         mkey_index[0x18];
	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_create_mkey_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         reserved_at_40[0x20];
	u8         pg_access[0x1];
	u8         mkey_umem_valid[0x1];
	u8         reserved_at_61[0x1e];
	struct mlx5_ifc_mkc_bits memory_key_mkey_entry;
	u8         reserved_at_280[0x80];
	u8         translations_octword_actual_size[0x20];
	u8         mkey_umem_id[0x20];
	u8         mkey_umem_offset[0x40];
	u8         reserved_at_380[0x500];
	struct mlx5_ifc_klm_bits klm_pas_mtt[];
};

struct mlx5_ifc_tisc_bits {
	u8         strict_lag_tx_port_affinity[0x1];
	u8         reserved_at_1[0x3];
	u8         lag_tx_port_affinity[0x04];
	u8         reserved_at_8[0x4];
	u8         prio[0x4];
	u8         reserved_at_10[0x10];
	u8         reserved_at_20[0x100];
	u8         reserved_at_120[0x8];
	u8         transport_domain[0x18];
	u8         reserved_at_140[0x8];
	u8         underlay_qpn[0x18];
	u8         reserved_at_160[0x3a0];
};

struct mlx5_ifc_create_tis_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         reserved_at_40[0x8];
	u8         tisn[0x18];
	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_create_tis_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         reserved_at_40[0xc0];
	struct mlx5_ifc_tisc_bits ctx;
};
#endif /* RTE_PMD_MLX5_PRM_H_ */
