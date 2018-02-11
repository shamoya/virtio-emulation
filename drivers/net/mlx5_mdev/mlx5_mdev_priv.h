/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#ifndef MLX5_MDEV_PRIV_H_
#define MLX5_MDEV_PRIV_H_

struct mlx5_mdev_priv {
	struct rte_eth_dev *edev;
	void	*base_addr;
	struct mlx5_mdev_context *dev_context;
	struct mlx5_mdev_db_page *db_page;
	int32_t page_size;
	int32_t cache_line_size;
	rte_spinlock_t lock; /* Lock for control functions. */
};

#endif

