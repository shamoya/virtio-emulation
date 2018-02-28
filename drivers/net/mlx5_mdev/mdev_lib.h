/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 Mellanox.
 */

#ifndef MDEV_LIB_H_
#define MDEV_LIB_H_

#include <stdint.h>

#include <rte_memory.h>

#include "mdev_prm.h"

#define MDEV_DEBUG(f_,...) printf((f_), __VA_ARGS__)

struct mlx5_mdev_cmd {
	struct mlx5_cmdq_entry	entry;
	uint8_t			rsvd0[2048 - sizeof(struct mlx5_cmdq_entry)];
	struct mlx5_cmd_block	ibox;
	uint8_t			rsvd1[1024 - sizeof(struct mlx5_cmd_block)];
	struct mlx5_cmd_block	obox;
	uint8_t			rsvd2[1024 - sizeof(struct mlx5_cmd_block)];
};

struct mlx5_mdev_extra_mailbox_space {
	rte_iova_t pa;
	union {
		void *addr;                   /**< Start virtual address. */
		uint64_t addr_64;             /**< Makes sure addr is always 64-bits */
	};
};

struct mlx5_mdev_memzone {
	uint64_t phys_addr;
	union {
		void *addr;                   /**< Start virtual address. */
		uint64_t addr_64;             /**< Makes sure addr is always 64-bits */
	};
} __attribute__((__packed__));

struct mdv_mr {
	struct mlx5_mdev_context *ctx;
};

struct mlx5_mdev_cap {
	uint32_t gen[MLX5_ST_SZ_DW(cmd_hca_cap)];
	uint32_t eth[MLX5_ST_SZ_DW(per_protocol_networking_offload_caps)];
	uint32_t ftn[MLX5_ST_SZ_DW(flow_table_nic_cap)];
};

typedef struct mlx5_mdev_memzone * (alloc_dma_memory_t)(void *owner, const char *name,
						size_t size, size_t align);

struct mlx5_mdev_context {
	void *owner;
	void *devx_ctx;	/* devx device */
	uint32_t page_size;
	uint32_t cache_line_size;
	struct mlx5_iseg *iseg; /* todo: should be removed when using ibv */
	alloc_dma_memory_t *alloc_function;  /* used for allocation of pinned mem */
	struct mlx5_mdev_cmd *cmd; /* todo: remove when using verbs */
	uint64_t cmd_pa; /* todo: remove when using verbs */
	struct mlx5_mdev_memzone ms; /* todo: remove when using verbs */
	struct mlx5_mdev_cap cap;
	uint32_t pd;
	uint32_t td;
	uint32_t uar;
	pthread_mutex_t		mutex;
};

#define MLX5_CAP_GEN(mdev, mcap) \
	MLX5_GET(cmd_hca_cap, mdev->cap.gen, mcap)
#define MLX5_CAP_ETH(mdev, mcap) \
	MLX5_GET(per_protocol_networking_offload_caps, mdev->cap.eth, mcap)
#define MLX5_CAP_FTN(mdev, mcap) \
	MLX5_GET(flow_table_nic_cap, mdev->cap.ftn, mcap)

int mlx5_mdev_cmd_exec(struct mlx5_mdev_context *ctx, void *in, int ilen,
			  void *out, int olen);

struct mlx5_mdev_context * mdev_open_device(void *owner,
					void *iseg,
					alloc_dma_memory_t alloc_function,
					void *devx_ctx);

int mlx5_mdev_alloc_pd(struct mlx5_mdev_context *ctx);
int mlx5_mdev_alloc_td(struct mlx5_mdev_context *ctx);

#endif
