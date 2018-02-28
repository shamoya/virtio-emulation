/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#ifndef MLX5_MDEV_PRIV_H_
#define MLX5_MDEV_PRIV_H_

#include <stdbool.h>
#include <sys/queue.h>

#include "mlx5_mdev_glue.h"
#include "mdev_lib.h"

struct mlx5_mdev_db_page {
	const struct rte_memzone *rte_mz;
	int num_db;
	int use_cnt;
	uint32_t free_records[];
};

struct mdev_cq_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t cqe; /* Minimum number of entries required for CQ */
	uint32_t create_flags;
	uint32_t eqn;
};

struct mdev_tis_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t td;
};

struct mdev_eq_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t eqe; /* Minimum number of entries required for CQ */
};

struct mdev_wq_attr {
	uint8_t wq_type;
	uint8_t page_offset;
	uint32_t pd;
	uint32_t uar_page;
	uint64_t dbr_addr;
	uint32_t hw_counter;
	uint32_t sw_counter;
	uint8_t wq_stride;
	uint8_t page_size;
	uint8_t wq_size;
};

struct mdev_sq_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t nelements;
	uint8_t rlkey;
	uint8_t fre;
	uint8_t inline_mode;
	uint32_t cqn;
	uint32_t tisn;
	struct mdev_wq_attr wq;
};

struct mdev_rq_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t nelements;
	uint8_t rlkey;
	uint8_t vsd;
	uint8_t csid; /* Counter set Id. */
	uint32_t cqn;
	uint32_t tirn;
	struct mdev_wq_attr wq;
};

struct mlx5_mdev_priv {
	struct rte_eth_dev *edev;
	void	*base_addr;
	struct mlx5_mdev_context *dev_context;
	struct mlx5_mdev_db_page *db_page;
	//int32_t page_size;
	//int32_t cache_line_size;
};

struct mdev_cq {
	struct mlx5_mdev_context *ctx;
	const struct rte_memzone *buf;
	//struct ibv_cq ibvcq;
	uint32_t out[MLX5_ST_SZ_DW(create_cq_out)];
	uint64_t dbr_phys_addr;
	volatile uint32_t *dbr_addr;
	uint32_t cqe_size;
	uint32_t uar_page;
	uint32_t cqn;
	uint32_t cons_index;
	uint32_t eqn;
	uint32_t ncqe;
};

struct mdev_eq {
	struct mlx5_mdev_context *ctx;
	const struct rte_memzone *buf;
	uint64_t dbr_phys_addr;
	volatile uint32_t *dbr_addr;
	uint32_t eqe_size;
	uint32_t uar_page;
	uint32_t cons_index;
	uint32_t eqn;
	uint32_t neqe;
};

struct mdev_tis {
	struct mlx5_mdev_context *ctx;
	uint32_t td;
	uint8_t priority;
	uint32_t tisn;
};

struct mdev_tir {
	struct mlx5_mdev_context *ctx;
	uint32_t td;
	uint8_t priority;
	uint32_t tirn;
};

struct mdev_wq {
	uint8_t wq_type;
	uint8_t stride_sz; /* The size of a WQ stride equals 2^log_wq_stride. */
	uint8_t page_sz; /* The size of a WQ stride equals 2^log_wq_stride. */
	uint8_t sz; /* The size of a WQ stride equals 2^log_wq_stride. */
	uint32_t pd;
	uint32_t uar_page;
	uint64_t dbr_phys_addr;
	volatile uint32_t *dbr_addr;
	uint32_t hw_counter;
	uint32_t sw_counter;
	uint32_t wqe_cnt;
	const struct rte_memzone *buf;
};

struct mdev_sq {
	struct mlx5_mdev_context *ctx;
	uint32_t sqn;
	uint32_t cqn;
	uint32_t tisn;
	struct mdev_wq wq;
};

struct mdev_rq {
	struct mlx5_mdev_context *ctx;
	struct mdev_wq wq;
	uint32_t rqn;
	uint32_t cqn;
	uint32_t tirn;
	uint8_t csid;
};

/*
 * TIR Info
 */

enum {
	MLX5_L3_PROT_TYPE_IPV4		= 0,
	MLX5_L3_PROT_TYPE_IPV6		= 1,
};

enum {
	MLX5_L4_PROT_TYPE_TCP		= 0,
	MLX5_L4_PROT_TYPE_UDP		= 1,
};

enum {
	MLX5_HASH_FIELD_SEL_SRC_IP	= 1 << 0,
	MLX5_HASH_FIELD_SEL_DST_IP	= 1 << 1,
	MLX5_HASH_FIELD_SEL_L4_SPORT	= 1 << 2,
	MLX5_HASH_FIELD_SEL_L4_DPORT	= 1 << 3,
	MLX5_HASH_FIELD_SEL_IPSEC_SPI	= 1 << 4,
};

/*
 * RX Hash Function flags.
*/
enum mdev_rx_hash_function {
        MLX5_MDEV_RX_HASH_FUNC_TOEPLITZ = 1 << 1,
        MLX5_MDEV_RX_HASH_FUNC_XOR = 1 << 0
};

/*
 * RX Hash flags, these flags allows to set which incoming packet field should
 * participates in RX Hash. Each flag represent certain packet's field,
 * when the flag is set the field that is represented by the flag will
 * participate in RX Hash calculation.
 * Notice: *IPV4 and *IPV6 flags can't be enabled together on the same QP
 * and *TCP and *UDP flags can't be enabled together on the same QP.
*/
enum mdev_tir_rx_hash_fields {
        MLX5_MDEV_RX_HASH_SRC_IPV4 = 1 << 0,
        MLX5_MDEV_RX_HASH_DST_IPV4 = 1 << 1,
        MLX5_MDEV_RX_HASH_SRC_IPV6 = 1 << 2,
        MLX5_MDEV_RX_HASH_DST_IPV6  = 1 << 3,
        MLX5_MDEV_RX_HASH_SRC_PORT_TCP = 1 << 4,
        MLX5_MDEV_RX_HASH_DST_PORT_TCP = 1 << 5,
        MLX5_MDEV_RX_HASH_SRC_PORT_UDP = 1 << 6,
        MLX5_MDEV_RX_HASH_DST_PORT_UDP = 1 << 7,
	/* Save bits for future fields */
	MLX5_MDEV_RX_HASH_INNER	= 1 << 30,
};

/*
 * RX Hash TIR configuration. Sets hash function, hash types and
 * Indirection table for QPs with enabled IBV_QP_INIT_ATTR_RX_HASH flag.
*/
enum mdev_tir_disp_type {
	MLX5_TIR_DISP_DIRECT = 0,
	MLX5_TIR_DISP_INDIRECT
};

struct mdev_ind_tir_info {
	uint32_t rqtn; /* Receive queue table number */
 	enum mdev_tir_rx_hash_fields rx_hash_fields_mask;
 	enum mdev_rx_hash_function hfunc;
        /* valid only for Toeplitz */
        uint8_t rx_hash_key_len;
        uint8_t rx_hash_key[128];
};

struct mdev_drct_tir_info {
	uint32_t rqn;
};

struct mdev_tir_attr {
	uint32_t td;
	enum mdev_tir_disp_type disp_type;
	bool tun_offload_en;
	union {
		struct mdev_ind_tir_info ind;
		struct mdev_drct_tir_info direct;
	};
	/* TODO: Add lro params */
	/* TPDO: Add offload params */
};

struct mdev_rqt {
	struct mlx5_mdev_context *ctx;
	uint32_t rqtn;
};

struct mdev_rqt_attr {
	uint32_t log_num_rq;
	/* Each entry is an array containing Rq numbers */
	uint32_t *rqn;
};

/* Flow Tables */

enum {
	MLX5_MDEV_FLOW_TABLE_TUNNEL_EN = 1,
};

enum mdev_fs_flow_table_type {
	FS_FT_NIC_RX		= 0x0,
	FS_FT_ESW_EGRESS_ACL	= 0x2,
	FS_FT_ESW_INGRESS_ACL	= 0x3,
	FS_FT_FDB		= 0X4,
	FS_FT_SNIFFER_RX	= 0X5,
	FS_FT_SNIFFER_TX	= 0X6,
	FS_FT_MAX_TYPE = FS_FT_SNIFFER_TX,
};

enum mdev_fs_flow_table_op_mod {
	FS_FT_OP_MOD_NORMAL = 0,
	FS_FT_OP_MOD_LAG_DEMUX = 1,
};

struct mdev_flow_table {
	//struct fs_node node;
	uint32_t id;
	uint16_t vport;
	uint32_t max_fte;
	uint32_t level;
	enum mdev_fs_flow_table_type type;
	enum mdev_fs_flow_table_op_mod op_mod;
#if 0
	struct {
		bool			active;
		unsigned int		required_groups;
		unsigned int		num_groups;
	} autogroup;
#endif
	/* Protect fwd_rules */
	// struct mutex lock;
	/* FWD rules that point on this flow table */
	// LIST_HEAD( , fwd_rules);
	uint32_t flags;
	//struct rhltable fgs_hash;
};
/* Interface routines */

uint64_t mlx5_get_dbrec(struct mlx5_mdev_priv *priv);

struct mdev_eq *
mlx5_mdev_create_eq(struct mlx5_mdev_priv *priv,
		    struct mdev_eq_attr *eq_attr);

int
mlx5_mdev_modify_eq(struct mdev_eq *eq,
		    struct mdev_eq_attr *eq_attr);

int
mlx5_mdev_destroy_eq(struct mdev_eq *eq);

struct mdev_cq *
mlx5_mdev_create_cq(struct mlx5_mdev_priv *priv,
		    struct mdev_cq_attr *cq_attr);

int
mlx5_mdev_modify_cq(struct mdev_cq *cq ,
		    struct mdev_cq_attr *cq_attr);

int
mlx5_mdev_destroy_cq(struct mdev_cq *cq);

struct mdev_tis *
mlx5_mdev_create_tis(struct mlx5_mdev_priv *priv,
		     struct mdev_tis_attr *tis_attr);

int
mlx5_mdev_modify_tis(struct mdev_tis *tis,
		     struct mdev_tis_attr *tis_attr);

int
mlx5_mdev_destroy_tis(struct mdev_tis *tis);

struct mdev_sq *
mlx5_mdev_create_sq(struct mlx5_mdev_priv *priv,
		    struct mdev_sq_attr *sq_attr);

int
mlx5_mdev_modify_sq(struct mdev_sq *sq,
	    	    struct mdev_sq_attr *sq_attr, int attr_mask);

int
mlx5_mdev_destroy_sq(struct mdev_sq *sq);

struct mdev_tir *
mlx5_mdev_create_tir(struct mlx5_mdev_priv *priv,
		     struct mdev_tir_attr *tir_attr);

int
mlx5_mdev_modify_tir(struct mdev_tir *tir,
		     struct mdev_tir_attr *tir_attr);

int
mlx5_mdev_destroy_tir(struct mdev_tir *tir);

struct mdev_rqt *
mlx5_mdev_create_rqt(struct mlx5_mdev_priv *priv,
		     struct mdev_rqt_attr *rqt_attr);

int
mlx5_mdev_modify_rqt(struct mdev_rqt *,
		     struct mdev_rqt_attr *rqt_attr);

int
mlx5_mdev_destroy_rqt(struct mdev_rqt *);

struct mdev_rq *
mlx5_mdev_create_rq(struct mlx5_mdev_priv *priv,
		    struct mdev_rq_attr *rq_attr);

int
mlx5_mdev_modify_rq(struct mdev_rq *rq,
		    struct mdev_rq_attr *rq_attr);

int
mlx5_mdev_destroy_rq(struct mdev_rq *rq);

#endif

