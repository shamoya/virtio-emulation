/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#ifndef MLX5_MDEV_PRIV_H_
#define MLX5_MDEV_PRIV_H_

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

uint64_t mlx5_get_dbrec(struct mlx5_mdev_priv *priv);

struct mdev_eq *
mlx5_mdev_create_eq(struct mlx5_mdev_priv *priv,
		    struct mdev_eq_attr *eq_attr);

struct mdev_cq *
mlx5_mdev_create_cq(struct mlx5_mdev_priv *priv,
		    struct mdev_cq_attr *cq_attr);

struct mdev_tis *
mlx5_mdev_create_tis(struct mlx5_mdev_priv *priv,
		    struct mdev_tis_attr *tis_attr);

struct mdev_sq *
mlx5_mdev_create_sq(struct mlx5_mdev_priv *priv,
		    struct mdev_sq_attr *sq_attr);

int
mlx5_mdev_modify_sq(struct mdev_sq *sq,
	    	    struct mdev_sq_attr *sq_attr, int attr_mask);

int
mlx5_mdev_destroy_eq(struct mdev_eq *eq);

int
mlx5_mdev_destroy_cq(struct mdev_cq *cq);

int
mlx5_mdev_destroy_tis(struct mdev_tis *tis);

int
mlx5_mdev_destroy_sq(struct mdev_sq *sq);

#endif

