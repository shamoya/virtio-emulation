/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2015 6WIND S.A.
 * Copyright 2015 Mellanox.
 */

#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <rte_ethdev_driver.h>

#include "mlx5_mdev.h"
#include "mlx5_mdev_rxtx.h"
#include "mlx5_mdev_utils.h"

/**
 * DPDK callback to enable promiscuous mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void
mlx5_promiscuous_enable(struct rte_eth_dev *dev)
{
	dev->data->promiscuous = 1;
	mlx5_traffic_restart(dev);
}

/**
 * DPDK callback to disable promiscuous mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void
mlx5_promiscuous_disable(struct rte_eth_dev *dev)
{
	dev->data->promiscuous = 0;
	mlx5_traffic_restart(dev);
}

/**
 * DPDK callback to enable allmulti mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void
mlx5_allmulticast_enable(struct rte_eth_dev *dev)
{
	dev->data->all_multicast = 1;
	mlx5_traffic_restart(dev);
}

/**
 * DPDK callback to disable allmulti mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void
mlx5_allmulticast_disable(struct rte_eth_dev *dev)
{
	dev->data->all_multicast = 0;
	mlx5_traffic_restart(dev);
}
