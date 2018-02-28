/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <math.h>

#include <rte_io.h>
#include <rte_pci.h>
#include <rte_ethdev_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eth_ctrl.h>

#include "mdev_prm.h"
#include "mlx5_mdev_priv.h"
#include "mlx5_mdev_utils.h"

static int
mdev_priv_create_eq(struct mlx5_mdev_context *ctx, struct mdev_eq *eq)
{
	void *cqc;
	uint32_t in[MLX5_ST_SZ_DW(create_eq_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_eq_out)];
	int err, status, syndrome;

	cqc = MLX5_ADDR_OF(create_eq_in, in, ctx);
	MLX5_SET(create_eq_in, in, opcode, MLX5_CMD_OP_CREATE_EQ);
	MLX5_ARRAY_SET64(create_eq_in, in, pas, 0,eq->buf->iova);

	MLX5_SET(eqc, cqc, log_eq_size, log2(eq->neqe));
	MLX5_SET(eqc, cqc, uar_page, eq->uar_page);
	MLX5_SET(eqc, cqc, log_page_size, log2(eq->buf->len /4096)); // TODO: from where ? MTT ???

	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_eq_out, out, status);
	syndrome = MLX5_GET(create_eq_out, out, syndrome);
	eq->eqn = MLX5_GET(create_eq_out, out, eqn);

	printf("mdev_priv_create_eq status %x, syndrome = %x\n",status, syndrome);

	return status;
}

#define cqe_sz_to_mlx_sz(size) \
	(size)== 64 ? 0 : 1

static int
mdev_priv_create_cq(struct mlx5_mdev_context *ctx, struct mdev_cq *cq)
{
	void *cqc;
	uint32_t in[MLX5_ST_SZ_DW(create_cq_in)] = {0};
	int err, status, syndrome;

	cqc = MLX5_ADDR_OF(create_cq_in, in, ctx);
	MLX5_SET(create_cq_in, in, opcode, MLX5_CMD_OP_CREATE_CQ);
	MLX5_ARRAY_SET64(create_cq_in, in, pas, 0, cq->buf->iova);
	MLX5_SET(cqc, cqc, c_eqn, cq->eqn);
	MLX5_SET(cqc, cqc, cqe_sz, cqe_sz_to_mlx_sz(cq->cqe_size));
	MLX5_SET(cqc, cqc, uar_page, cq->uar_page);
	MLX5_SET(cqc, cqc, log_page_size, log2(cq->buf->len /4096)); // TODO: from where ? MTT ???
	MLX5_SET64(cqc, cqc, dbr_addr, cq->dbr_phys_addr);
	MLX5_SET(cqc, cqc, log_cq_size, log2(cq->ncqe)); // WAS: cq->buf->len
	MLX5_SET(cqc, cqc, oi, 0);
	printf("mdev_priv_create_cq uar %x, dbrec = %lx\n",cq->uar_page, cq->dbr_phys_addr);
	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), cq->out, sizeof(cq->out));
	if (err)
		return (err);
	cq->ctx = ctx;
	cq->cqn = MLX5_GET(create_cq_out, cq->out, cqn);
	cq->cons_index = 0;
	// cq->arm_sn     = 0;
	status = MLX5_GET(create_cq_out, cq->out, status);
	syndrome = MLX5_GET(create_cq_out, cq->out, syndrome);
	printf("mdev_priv_create_cq status %x, syndrome = %x cqn %d\n",status, syndrome, cq->cqn);

	return 0;
}


static int
mdev_priv_create_tis(struct mlx5_mdev_context *ctx, struct mdev_tis *tis)
{
	void *tisc;
	uint32_t in[MLX5_ST_SZ_DW(create_tis_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_tis_out)];
	int err, status, syndrome;

	tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);
	MLX5_SET(create_tis_in, in, opcode, MLX5_CMD_OP_CREATE_TIS);
	MLX5_SET(tisc, tisc, prio, (tis->priority)<<1);
	MLX5_SET(tisc, tisc, transport_domain, tis->td);
	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);

	status = MLX5_GET(create_tis_out, out, status);
	syndrome = MLX5_GET(create_tis_out, out, syndrome);
	if(!status)
		tis->tisn = MLX5_GET(create_tis_out, out, tisn);
	printf("mdev_priv_create_tis status %x, syndrome = %x\n",
		status, syndrome);

	return status;
}

static int
mdev_priv_create_sq(struct mlx5_mdev_context *ctx, struct mdev_sq *sq)
{
	void *sqc;
	void *wqc;
	uint32_t in[MLX5_ST_SZ_DW(create_sq_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_sq_out)] = {0};
	int err, status, syndrome;

	MLX5_SET(create_sq_in, in, opcode, MLX5_CMD_OP_CREATE_SQ);

	sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
	MLX5_SET(sqc, sqc, cqn, sq->cqn);
	MLX5_SET(sqc, sqc, tis_lst_sz, 1);
	MLX5_SET(sqc, sqc, tis_num_0, sq->tisn);

	wqc = MLX5_ADDR_OF(sqc, sqc, wq);
	MLX5_SET(wq, wqc, wq_type, 0x1);
	MLX5_SET(wq, wqc, pd, sq->wq.pd);
	MLX5_SET64(wq, wqc, dbr_addr, sq->wq.dbr_phys_addr);
	MLX5_SET(wq, wqc, log_wq_stride, 6);
	MLX5_SET(wq, wqc, log_wq_pg_sz, log2(sq->wq.buf->len /4096));
	MLX5_SET(wq, wqc, log_wq_sz, log2(sq->wq.buf->len>>6));
	MLX5_ARRAY_SET64(wq, wqc, pas, 0, sq->wq.buf->iova);

	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_sq_out, out, status);
	syndrome = MLX5_GET(create_sq_out, out, syndrome);
	printf("mdev_priv_create_sq status %x, syndrome = %x\n",status, syndrome);
	if(!status)
		sq->sqn = MLX5_GET(create_sq_out, out, sqn);
	return status;
}

static int
mdev_priv_create_tir_direct(struct mlx5_mdev_context *ctx,
			    struct mdev_tir_attr *info,
			    uint32_t *rqtn)
{
	void *tirc;
	uint32_t in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_tir_out)];
	int err, status, syndrome;

	MLX5_SET(create_tir_in, in, opcode, MLX5_CMD_OP_CREATE_TIR);
	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, transport_domain, info->td);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIR_DISP_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, info->direct.rqn);  // FIXME ?
	if (info->tun_offload_en)
		MLX5_SET(tirc, tirc, tunneled_offload_en, 1);

	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_tir_out, out, status);
	syndrome = MLX5_GET(create_tir_out, out, syndrome);
	if(!status)
		*rqtn = MLX5_GET(create_tir_out, out, tirn);
	printf("mdev_priv_create_tir status %x, syndrome = %x\n",status, syndrome);
	return status;
}

static int
mdev_priv_create_tir_indirect(struct mlx5_mdev_context *ctx,
			      struct mdev_tir_attr *info,
			      uint32_t *rqtn)
{
	void *tirc;
	void *hfso;
	uint32_t selected_fields = 0;
	uint32_t in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_tir_out)];
	int err, status, syndrome;

	if (info->tun_offload_en && 0) { // TODO: addd support for: !tunnel_offload_supported(dev->mdev)) {
		ERROR("tunnel offloads isn't supported\n");
		return -EOPNOTSUPP;
	}
	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_INNER) &&
	    !info->tun_offload_en) {
		ERROR("Tunnel offloads must be set for inner RSS\n");
		return -EOPNOTSUPP;
	}

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIR_DISP_INDIRECT);
	MLX5_SET(tirc, tirc, indirect_table, info->ind.rqtn);
	MLX5_SET(tirc, tirc, transport_domain, info->td);

	hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);

	if (info->tun_offload_en)
		MLX5_SET(tirc, tirc, tunneled_offload_en, 1);

	if (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_INNER)
		hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_inner);
	else
		hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);

	switch (info->ind.hfunc) {
	case MLX5_MDEV_RX_HASH_FUNC_TOEPLITZ:
	{
		void *rss_key = MLX5_ADDR_OF(tirc, tirc, rx_hash_toeplitz_key);
		size_t len = MLX5_FLD_SZ_BYTES(tirc, rx_hash_toeplitz_key);
		if (len != info->ind.rx_hash_key_len) {
			ERROR("Invalid Rx hash key len(expected %zu, got %d)",
			      len, info->ind.rx_hash_key_len);
			err = -EINVAL;
			goto err;
		}
		MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_MDEV_RX_HASH_FUNC_TOEPLITZ);
		MLX5_SET(tirc, tirc, rx_hash_symmetric, 1);
		memcpy(rss_key, info->ind.rx_hash_key, len);
		break;
	}
	default:
		ERROR("Unsupported Rx hash function (%d)", info->ind.hfunc);
		err = -EOPNOTSUPP;
		goto err;
	}
#if 0 // TODO: check how to implement this
	if (!info->ind.rx_hash_fields_mask) {
		/* special case when this TIR serves as steering entry without hashing */
		if (!init_attr->rwq_ind_tbl->log_ind_tbl_size)
			goto create_tir;
		err = -EINVAL;
		goto err;
	}
#endif
	if (((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV4) ||
	     (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV4)) &&
	     ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV6) ||
	     (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV6))) {
		err = -EINVAL;
		goto err;
	}

	/* If none of IPV4 & IPV6 SRC/DST was set - this bit field is ignored */
	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV4) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV4))
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
	else if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV6) ||
		 (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV6))
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);

	if (((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_TCP) ||
	     (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_TCP)) &&
	     ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_UDP) ||
	     (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_UDP))) {
		err = -EINVAL;
		goto err;
	}

	/* If none of TCP & UDP SRC/DST was set - this bit field is ignored */
	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_TCP) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_TCP))
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_TCP);
	else if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_UDP) ||
		 (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_UDP))
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_UDP);

	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV4) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_IPV6))
		selected_fields |= MLX5_HASH_FIELD_SEL_SRC_IP;

	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV4) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_IPV6))
		selected_fields |= MLX5_HASH_FIELD_SEL_DST_IP;

	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_TCP) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_SRC_PORT_UDP))
		selected_fields |= MLX5_HASH_FIELD_SEL_L4_SPORT;

	if ((info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_TCP) ||
	    (info->ind.rx_hash_fields_mask & MLX5_MDEV_RX_HASH_DST_PORT_UDP))
		selected_fields |= MLX5_HASH_FIELD_SEL_L4_DPORT;

	MLX5_SET(rx_hash_field_select, hfso, selected_fields, selected_fields);

//create_tir:
	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		goto err;
	status = MLX5_GET(create_tir_out, out, status);
	syndrome = MLX5_GET(create_tir_out, out, syndrome);
	if (!status)
		*rqtn = MLX5_GET(create_tir_out, out, tirn);
	printf("mdev_priv_create_tir status %x, syndrome = %x\n",status, syndrome);
	return status;

err:
	return err;
}

static int
mdev_priv_create_rq(struct mlx5_mdev_context *ctx, struct mdev_rq *rq)
{
	void *rqc;
	void *wqc;
	uint32_t in[MLX5_ST_SZ_DW(create_rq_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_rq_out)] = {0};
	int err, status, syndrome;

	MLX5_SET(create_rq_in, in, opcode, MLX5_CMD_OP_CREATE_RQ);
	MLX5_SET(create_rq_in, in, op_mod, 0);

	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	MLX5_SET(rqc, rqc, rlky, 1);
	MLX5_SET(rqc, rqc, delay_drop_en, 0);
	MLX5_SET(rqc, rqc, scatter_fcs, 0);
	MLX5_SET(rqc, rqc, vsd, 1);		// TODO: vlan stripping as a parameter.
	MLX5_SET(rqc, rqc, mem_rq_type, 0);	// TODO: add a parameter ? inline vs. remote
	MLX5_SET(rqc, rqc, state, 0);
	MLX5_SET(rqc, rqc, flush_in_error_en, 0); // TODO: What value to put here ?
	MLX5_SET(rqc, rqc, user_index, 0);
	//MLX5_SET(rqc, rqc, hairpin, 1);	FIXME !!!
	MLX5_SET(rqc, rqc, cqn, rq->cqn);
	MLX5_SET(rqc, rqc, counter_set_id, rq->csid); // FIXME: get counter set using ALLOC_Q_COUNTER command.
	MLX5_SET(rqc, rqc, rmpn, 0);
	//MLX5_SET(rqc, rqc, peer_sq, ??);	FIXME !!!
	//MLX5_SET(rqc, rqc, peer_vhca, ??);	FIXME !!!

	wqc = MLX5_ADDR_OF(rqc, rqc, wq);
	MLX5_SET(wq, wqc, wq_type, 0x1);	/* Cyclic descriptors */
	MLX5_SET(wq, wqc, pd, rq->wq.pd);
	MLX5_SET64(wq, wqc, dbr_addr, rq->wq.dbr_phys_addr);
	MLX5_SET(wq, wqc, log_wq_stride, 6);
	MLX5_SET(wq, wqc, log_wq_pg_sz, log2(rq->wq.buf->len / 4096));
	MLX5_SET(wq, wqc, log_wq_sz, log2(rq->wq.buf->len >> 6));
	MLX5_ARRAY_SET64(wq, wqc, pas, 0, rq->wq.buf->iova); // TODO: Break down to 4096b pages ?

	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_rq_out, out, status);
	syndrome = MLX5_GET(create_rq_out, out, syndrome);
	printf("mdev_priv_create_rq status %x, syndrome = %x\n",status, syndrome);
	if(!status)
		rq->rqn = MLX5_GET(create_rq_out, out, rqn);
	return status;
}

static int
mdev_priv_create_rqt(struct mlx5_mdev_context *mctx,
		     struct mdev_rqt_attr *rqt_attr,
		     uint32_t *rqtn)
{
	int num_rxqs = 1 << rqt_attr->log_num_rq;
	int rxq_max = 128;  // FIXME take from HCA
	uint32_t in[MLX5_ST_SZ_DW(create_rqt_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_rqt_out)] = {0};
	void *rqtc;
	uint32_t *rq_arr;
	int err, status, syndrome, i;

	if (num_rxqs > rxq_max) {
		ERROR("num_rxqs (%d) > max allowed (%d)", num_rxqs, rxq_max);
		return -EINVAL;
	}
	MLX5_SET(create_rqt_in, in, opcode, MLX5_CMD_OP_CREATE_RQT);
	rqtc = MLX5_ADDR_OF(create_rqt_in, in, ctx);
	MLX5_SET(rqtc, rqtc, rqt_max_size, rxq_max);
	MLX5_SET(rqtc, rqtc, rqt_actual_size, num_rxqs);
	/* fill the rqn list */
	rq_arr = (uint32_t *)MLX5_ADDR_OF(rqtc, rqtc, rq_num);
	for (i = 0; i < num_rxqs; i++)
		rq_arr[i] = rte_cpu_to_be_32(rqt_attr->rqn[i]);
	err = mlx5_mdev_cmd_exec(mctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_rqt_out, out, status);
	syndrome = MLX5_GET(create_rqt_out, out, syndrome);
	printf("mdev_priv_create_rqt status %x, syndrome = %x\n",status, syndrome);
	if(!status)
		*rqtn = MLX5_GET(create_rqt_out, out, rqtn);
	return status;
}

static int __rte_unused
mdev_priv_create_flow_table(struct mlx5_mdev_context *mctx,
			    uint16_t vport,
			    enum mdev_fs_flow_table_op_mod op_mod,
			    enum mdev_fs_flow_table_type type,
			    unsigned int level,
			    unsigned int log_size,
			    struct mdev_flow_table *next_ft,
			    unsigned int *table_id,
			    uint32_t flags)
{
	int en_encap_decap = !!(flags & MLX5_MDEV_FLOW_TABLE_TUNNEL_EN);
	uint32_t out[MLX5_ST_SZ_DW(create_flow_table_out)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_flow_table_in)]   = {0};
	int err, status, syndrome;

	MLX5_SET(create_flow_table_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_TABLE);

	MLX5_SET(create_flow_table_in, in, table_type, type);
	MLX5_SET(create_flow_table_in, in, flow_table_context.level, level);
	MLX5_SET(create_flow_table_in, in, flow_table_context.log_size, log_size);
	if (vport) {
		MLX5_SET(create_flow_table_in, in, vport_number, vport);
		MLX5_SET(create_flow_table_in, in, other_vport, 1);
	}

	MLX5_SET(create_flow_table_in, in, flow_table_context.decap_en,
		 en_encap_decap);
	MLX5_SET(create_flow_table_in, in, flow_table_context.encap_en,
		 en_encap_decap);

	switch (op_mod) {
	case FS_FT_OP_MOD_NORMAL:
		if (next_ft) {
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.table_miss_action, 1);
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.table_miss_id,
				 next_ft->id);
		}
		break;

	case FS_FT_OP_MOD_LAG_DEMUX:
		MLX5_SET(create_flow_table_in, in, op_mod,
		         FS_FT_OP_MOD_LAG_DEMUX);
		if (next_ft)
			MLX5_SET(create_flow_table_in, in,
				 flow_table_context.lag_master_next_table_id,
				 next_ft->id);
		break;
	}

	err = mlx5_mdev_cmd_exec(mctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return (err);
	status = MLX5_GET(create_flow_table_out, out, status);
	syndrome = MLX5_GET(create_flow_table_out, out, syndrome);
	printf("mdev_priv_create_flow_table status %x, syndrome = %x\n",
		status, syndrome);
	if(!status)
		*table_id = MLX5_GET(create_flow_table_out, out,
				     table_id);
	return status;
}

struct mdev_eq *
mlx5_mdev_create_eq(struct mlx5_mdev_priv *priv,
		    struct mdev_eq_attr *eq_attr)
{
	uint32_t eqe_size = 64;
	int log_max_cq_sz = 24; // TODO take from QUERY_HCA_CAP
	struct mdev_eq *eq;
	struct mlx5_mdev_context *ctx = priv->dev_context;
	uint32_t neqe, eq_size;
	int ret;

	if (!eq_attr->eqe) {
		return NULL;
	}
	eq = rte_zmalloc("mdev_eq", sizeof(*eq), ctx->cache_line_size); // TODO: make it numa node aware ?
	if(!eq)
		return NULL;
	neqe = 1UL << log2above(eq_attr->eqe + 1);
	eq_size = neqe * eqe_size;
	if ((neqe > 1UL << log_max_cq_sz) ||
	    (neqe < (eq_attr->eqe + 1))) {
		goto err_spl;
	}
	eq->ctx = ctx;
	eq->neqe = neqe;
	eq->buf = rte_eth_dma_zone_reserve(ctx->owner, "eq_buffer",
	                                   0, eq_size, ctx->page_size,
	                                   priv->edev->data->numa_node);
	if (!eq->buf)
		goto err_spl;

	eq->uar_page = ctx->uar;

	ret = mdev_priv_create_eq(ctx, eq);
	printf("create eq res == %d\n", ret);
	if (ret)
		goto err_ccq;
	return eq;
err_ccq:
	//mlx5_mdev_dealloc_uar(ctx, eq->uar_page); // fixme : remove
err_spl:
	//if (eq->buf)
	//	mdev_dealloc_cq_buf(ctx, eq->buf);
	//if (eq->dbrec)
	//	mlx5_return_dbrec(priv, eq->dbrec);
	//rte_free(eq);
	return NULL;
}

int
mlx5_mdev_modify_eq(struct mdev_eq *eq __rte_unused,
		    struct mdev_eq_attr *eq_attr __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_eq(struct mdev_eq *eq __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

struct mdev_cq *
mlx5_mdev_create_cq(struct mlx5_mdev_priv *priv,
		    struct mdev_cq_attr *cq_attr)
{
	uint32_t cqe_size = 64; // TODO make it a user parameter ?
	struct mdev_cq *cq;
	struct mlx5_mdev_context *ctx = priv->dev_context;
	uint32_t ncqe, cq_size;
	uint64_t offset = mlx5_get_dbrec(priv);
	int ret;


	if (!cq_attr->cqe || (offset == -1ULL)) {
		return NULL;
	}
	cq = rte_zmalloc("struct ibv_cq", sizeof(*cq), ctx->cache_line_size); // TODO: make it numa node aware ?
	if(!cq)
		return NULL;
	cq->ncqe = log2above(cq_attr->cqe + 1);;
	ncqe = 1UL << cq->ncqe;
	cq_size = ncqe * cqe_size;
	cq->cqe_size = cqe_size;
	cq->dbr_addr = (void *)((char *)(priv->db_page->rte_mz->addr) + offset);
	cq->dbr_phys_addr = priv->db_page->rte_mz->iova + offset;
	cq->uar_page = ctx->uar;
	/* Fill info for create CQ */
	cq->eqn = cq_attr->eqn;
	cq->buf = rte_eth_dma_zone_reserve(ctx->owner, "cq_buffer", 0, cq_size, cq_size,
						priv->edev->data->numa_node);
	cq->ctx = cq_attr->ctx;
	ret = mdev_priv_create_cq(ctx, cq);
	if (ret)
		goto err_ccq;
	printf("create CQ res == %d\n",ret);
	return cq;
err_ccq:
	//mlx5_mdev_dealloc_uar(ctx, cq->uar_page); // fixme : remove
//err_spl:
	//if (cq->buf)
	//	mdev_dealloc_cq_buf(ctx, cq->buf);
	//if (cq->dbrec)
	//	mlx5_return_dbrec(priv, cq->dbrec);
	rte_free(cq);
	return NULL;
}

int
mlx5_mdev_modify_cq(struct mdev_cq *cq __rte_unused,
		    struct mdev_cq_attr *cq_attr __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_cq(struct mdev_cq *cq __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}


struct mdev_tis *
mlx5_mdev_create_tis(struct mlx5_mdev_priv *priv,
		     struct mdev_tis_attr *tis_attr)
{
	struct mlx5_mdev_context *ctx = priv->dev_context;
	struct mdev_tis *tis;
	int ret;

	if (!tis_attr->td) {
		return NULL;
	}
	tis = rte_zmalloc("tis", sizeof(*tis), ctx->cache_line_size);
	if(!tis)
		return NULL;

	tis->ctx = ctx;
	tis->td = tis_attr->td;

	ret = mdev_priv_create_tis(ctx, tis);
	printf("create tis res == %d\n", ret);
	if (ret)
		goto err_tis;
	return tis;
err_tis:
	rte_free(tis);
	return NULL;
}

int
mlx5_mdev_modify_tis(struct mdev_tis *tis __rte_unused,
		     struct mdev_tis_attr *tis_attr __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_tis(struct mdev_tis *tis __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

struct mdev_sq *
mlx5_mdev_create_sq(struct mlx5_mdev_priv *priv,
		    struct mdev_sq_attr *sq_attr)
{
	struct mlx5_mdev_context *ctx = priv->dev_context;
	struct mdev_sq *sq;
	uint64_t offset = mlx5_get_dbrec(priv);
	int ret;

	if (offset == -1ULL)
		return NULL;
	sq = rte_zmalloc("sq", sizeof(*sq), ctx->cache_line_size);
	if(!sq)
		return NULL;
	sq->ctx = ctx;
	sq->wq.pd = sq_attr->wq.pd;
	sq->cqn = sq_attr->cqn;
	sq->tisn = sq_attr->tisn;
	sq->wq.dbr_phys_addr = priv->db_page->rte_mz->iova + offset;
	sq->wq.dbr_addr = (void *)((char *)(priv->db_page->rte_mz->addr) + offset);
	sq->wq.uar_page = ctx->uar;
	sq->wq.wqe_cnt = log2above(sq_attr->nelements);
	sq->wq.buf = rte_eth_dma_zone_reserve(ctx->owner,
	                                      "sq_buffer", 0,
	                                      (1 << sq->wq.wqe_cnt) * 64, 4096,
	                                      priv->edev->data->numa_node);
	ret = mdev_priv_create_sq(ctx, sq);
	printf("create sq res == %d\n", ret);
	if (ret)
		goto err_sq;
	return sq;
err_sq:
	rte_free(sq);
	return NULL;
}

int
mlx5_mdev_modify_sq(struct mdev_sq *sq __rte_unused,
		    struct mdev_sq_attr *sq_attr __rte_unused,
		    int attr_mask __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_sq(struct mdev_sq *sq __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

struct mdev_tir *
mlx5_mdev_create_tir(struct mlx5_mdev_priv *priv,
		     struct mdev_tir_attr *tir_attr)
{
	struct mlx5_mdev_context *ctx = priv->dev_context;
	int ret;
	struct mdev_tir *tir;

	if (!tir_attr->td) {
		return NULL;
	}
	tir = rte_zmalloc("tir", sizeof(*tir), ctx->cache_line_size);
	if(!tir)
		return NULL;

	tir->ctx = ctx;
	tir->td = tir_attr->td;
	if (tir_attr->disp_type == MLX5_TIR_DISP_DIRECT)
		ret = mdev_priv_create_tir_direct(ctx, tir_attr, &tir->tirn);
	else
		ret = mdev_priv_create_tir_indirect(ctx, tir_attr, &tir->tirn);
	printf("create tir res == %d\n", ret);
	if (ret)
		goto err_tir;
	return tir;
err_tir:
	rte_free(tir);
	return NULL;
}

int
mlx5_mdev_modify_tir(struct mdev_tir *tir  __rte_unused,
		     struct mdev_tir_attr *tir_attr  __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_tir(struct mdev_tir *tir __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

struct mdev_rqt *
mlx5_mdev_create_rqt(struct mlx5_mdev_priv *priv,
		     struct mdev_rqt_attr *rqt_attr)
{
	struct mlx5_mdev_context *ctx = priv->dev_context;
	struct mdev_rqt *rqt = NULL;
	int ret;

	rqt = rte_zmalloc("rqt", sizeof(*rqt), ctx->cache_line_size);
	if(!rqt)
		goto err;

	rqt->ctx = ctx;
	ret = mdev_priv_create_rqt(ctx, rqt_attr, &rqt->rqtn);
	printf("create rqt res == %d\n", ret);
	if (ret)
		goto err;

	return rqt;
err:
	rte_free(rqt);
	return NULL;

}

int
mlx5_mdev_modify_rqt(struct mdev_rqt *rqt __rte_unused,
		     struct mdev_rqt_attr *rqt_attr __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

int
mlx5_mdev_destroy_rqt(struct mdev_rqt *rqt __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

struct mdev_rq *
mlx5_mdev_create_rq(struct mlx5_mdev_priv *priv,
		    struct mdev_rq_attr *rq_attr)
{
	struct mlx5_mdev_context *ctx = priv->dev_context;
	struct mdev_rq *rq;
	uint64_t offset = mlx5_get_dbrec(priv);
	int ret;

	if (offset == -1ULL)
		return NULL;
	rq = rte_zmalloc("rq", sizeof(*rq), ctx->cache_line_size);
	if(!rq)
		return NULL;
	rq->ctx = ctx;
	rq->wq.pd = rq_attr->wq.pd;
	rq->cqn = rq_attr->cqn;
	rq->tirn = rq_attr->tirn;
	rq->wq.dbr_phys_addr = priv->db_page->rte_mz->iova + offset;
	rq->wq.dbr_addr = (void *)((char *)(priv->db_page->rte_mz->addr) + offset);
	rq->wq.uar_page = ctx->uar;
	rq->wq.wqe_cnt = log2above(rq_attr->nelements);
	rq->wq.buf = rte_eth_dma_zone_reserve(ctx->owner,
	                                      "sq_buffer", 0,
	                                      (1 << rq->wq.wqe_cnt) * 64, 4096,
	                                      priv->edev->data->numa_node);
	ret = mdev_priv_create_rq(ctx, rq);
	printf("create rq res == %d\n", ret);
	if (ret)
		goto err_sq;
	return rq;
err_sq:
	rte_free(rq);
	return NULL;
}

int
mlx5_mdev_destroy_rq(struct mdev_rq *rq __rte_unused)
{
	ERROR("%s: Not implemented yet!!!", __func__);
	return -1;
}

#if 0 // TODO: Add  Flow table support
struct mdev_flow_table *
mlx5_mdev_create_flow_table(struct mlx5_flow_namespace *ns,
		       struct mlx5_flow_table_attr *ft_attr);
return __mlx5_create_flow_table(ns, ft_attr, FS_FT_OP_MOD_NORMAL, 0);
#endif

