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

#include <rte_io.h>
#include <rte_pci.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ethdev_pci.h>
#include <rte_eth_ctrl.h>

#include "mdev_lib.h"
#include "mlx5_mdev_priv.h"
#include "mlx5_mdev.h"


static inline struct mlx5_mdev_memzone * alloc_pinned(void * edev,
					const char *name,
					size_t size,
					size_t align)
{
	const struct rte_memzone *rte_mz = rte_eth_dma_zone_reserve(edev,
					name, 0, size, align,
					((struct rte_eth_dev *)edev)->data->numa_node);
	struct mlx5_mdev_memzone *mz = rte_zmalloc("mdev", sizeof(struct mlx5_mdev_memzone), 64);

	if(!mz)
		return mz;
	mz->addr = rte_mz->addr;
	mz->phys_addr = rte_mz->iova;
	return mz;
}

static int mlx5_mdev_dev_start(struct rte_eth_dev *edev)
{
	edev = edev;

	return 0;
}

static void mlx5_mdev_infos_get(struct rte_eth_dev *edev, // TODO: review field-by-field, considering dev caps
				struct rte_eth_dev_info *info)
{
	info->pci_dev		 = RTE_ETH_DEV_TO_PCI(edev);
	info->min_rx_bufsize	 = 32;
	info->max_rx_pktlen	 = 65536;
	info->max_rx_queues	 = 1;
	info->max_tx_queues	 = 1;
	info->max_mac_addrs	 = 1;
	info->rx_offload_capa	 = DEV_RX_OFFLOAD_IPV4_CKSUM;
	info->rx_offload_capa	|= DEV_RX_OFFLOAD_UDP_CKSUM;
	info->rx_offload_capa	|= DEV_RX_OFFLOAD_TCP_CKSUM;
	info->rx_offload_capa	|= DEV_RX_OFFLOAD_VLAN_STRIP;
	info->tx_offload_capa	 = DEV_TX_OFFLOAD_IPV4_CKSUM;
	info->tx_offload_capa	|= DEV_TX_OFFLOAD_UDP_CKSUM;
	info->tx_offload_capa	|= DEV_TX_OFFLOAD_TCP_CKSUM;
	info->speed_capa	 = ETH_LINK_SPEED_10G;
}

static const struct eth_dev_ops mlx5_mdev_dev_ops = { // TODO...
	.dev_start		= mlx5_mdev_dev_start,
	.dev_infos_get		= mlx5_mdev_infos_get,
};

static int mlx5_mdev_init(struct rte_eth_dev *edev)
{

	struct mlx5_mdev_priv *priv = edev->data->dev_private;
	struct rte_pci_device *pdev = RTE_ETH_DEV_TO_PCI(edev);
	printf("oooOri in mlx5_mdev_init start\n");

	priv->edev = edev;

	edev->data->dev_private = priv;

	edev->dev_ops = &mlx5_mdev_dev_ops;

	priv->base_addr = (void *)pdev->mem_resource[0].addr;
	priv->cache_line_size = RTE_CACHE_LINE_SIZE;
	priv->page_size = 4096; //oooOri todo change to page size
	priv->dev_context = mdev_open_device(priv->edev,
						priv->base_addr,
						alloc_pinned);
	struct mdev_cq_attr cq_attr = {0};
	struct mdev_eq_attr eq_attr = {0};
	struct mdev_tis_attr tis_attr = {0};

	cq_attr.cqe = 64;
	cq_attr.ctx = priv->dev_context;
	eq_attr.ctx = priv->dev_context;
	eq_attr.eqe = 64;
	struct mdev_eq * eq =
		mlx5_mdev_create_eq(priv, &eq_attr);
	cq_attr.eqn = eq->eqn;
	struct mdev_cq * cq =
			mlx5_mdev_create_cq(priv, &cq_attr);
	tis_attr.ctx = priv->dev_context;
	tis_attr.td = priv->dev_context->td;
	struct mdev_tis *tis = mlx5_mdev_create_tis(priv, &tis_attr);

	printf("ooooOri in mlx5_mdev_init after cq = %x, %x, %x\n", eq->eqn, cq->cqn, tis->tisn);

	printf("ooooOri in mlx5_mdev_init end\n");
	return 0;
}

static int mlx5_mdev_uninit(struct rte_eth_dev *edev)
{

	edev = edev;


	return 0;
}

static int mlx5_mdev_pci_probe(__rte_unused struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pdev)
{
	return rte_eth_dev_pci_generic_probe(pdev, sizeof(struct mlx5_mdev_priv),
			mlx5_mdev_init);
}

static int mlx5_mdev_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, mlx5_mdev_uninit);
}

static const struct rte_pci_id mlx5_mdev_pci_id_map[] = {
	{ RTE_PCI_DEVICE(0x15b3, 0x1014) }, /* ConnectX-4   VF */
	{ RTE_PCI_DEVICE(0x15b3, 0x1016) }, /* ConnectX-4Lx VF */
	{ RTE_PCI_DEVICE(0x15b3, 0x1018) }, /* ConnectX-5   VF */
	{ RTE_PCI_DEVICE(0x15b3, 0x101a) }, /* ConnectX-5Ex VF */
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver mlx5_mdev_pci_driver = {
	.id_table	= mlx5_mdev_pci_id_map,
	.drv_flags	= RTE_PCI_DRV_NEED_MAPPING,
	.probe		= mlx5_mdev_pci_probe,
	.remove		= mlx5_mdev_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_mlx5_mdev, mlx5_mdev_pci_driver);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5_mdev, mlx5_mdev_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5_mdev, "* igb_uio | uio_pci_generic | vfio-pci");
