/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#ifndef MLX5_MDEV_PRIV_H_
#define MLX5_MDEV_PRIV_H_

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

struct mdev_eq_attr {
	struct mlx5_mdev_context *ctx;
	uint32_t eqe; /* Minimum number of entries required for CQ */
};

struct mlx5_mdev_priv {
	struct rte_eth_dev *edev;
	void	*base_addr;
	struct mlx5_mdev_context *dev_context;
	struct mlx5_mdev_db_page *db_page;
	int32_t page_size;
	int32_t cache_line_size;
	rte_spinlock_t lock; /* Lock for control functions. */
};

struct mdev_cq {
	struct mlx5_mdev_context *ctx;
	const struct rte_memzone *buf;
	uint64_t dbrec;
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
	uint64_t dbrec;
	uint32_t eqe_size;
	uint32_t uar_page;
	uint32_t cons_index;
	uint32_t eqn;
	uint32_t neqe;
};

int64_t mlx5_get_dbrec(struct mlx5_mdev_priv *priv);


struct mdev_eq *
mlx5_mdev_create_eq(struct mlx5_mdev_priv *priv,
		    struct mdev_eq_attr *eq_attr);
struct mdev_cq *
mlx5_mdev_create_cq(struct mlx5_mdev_priv *priv,
		    struct mdev_cq_attr *cq_attr);

static inline unsigned int
log2above(unsigned int v)
{
	unsigned int l;
	unsigned int r;

	for (l = 0, r = 0; (v >> 1); ++l, v >>= 1)
		r |= (v & 1);
	return l + r;
}
#endif

