/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <rte_bus_pci.h>
#include <rte_errno.h>
#include <rte_vdpa.h>
#include <rte_malloc.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "mlx5_glue.h"
#include "mlx5_defs.h"
#include "mlx5_utils.h"
#include "mlx5.h"
#include "mlx5_prm.h"

/** Driver Static values in the absence of device VIRTIO emulation support */
#define MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED 1

/** Driver Static values in the absence of device VIRTIO emulation support */
#define MLX5_VDPA_SW_NOTIFY_STRIDE 4

#define MLX5_VDPA_FEATURES ((1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
			    (1ULL << VIRTIO_F_VERSION_1))

#define MLX5_VDPA_PROTOCOL_FEATURES \
			    ((1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER))

/** Driver-specific log messages type. */
int mlx5_vdpa_logtype;

struct mlx5_vdpa_caps {
	uint32_t dump_mkey;
	uint16_t max_num_virtqs;
	uint64_t virtio_net_features;
	uint64_t virtio_protocol_features;
	uint16_t notify_stride; /* Size in bytes of each queue notify area. */
};

struct vdpa_priv {
	int id; /* vDPA device id. */
	struct rte_pci_device *pdev;
	struct ibv_context *ctx; /* Device context. */
	struct rte_vdpa_dev_addr dev_addr;
	struct mlx5_vdpa_caps caps;
};

struct vdpa_priv_list {
	TAILQ_ENTRY(vdpa_priv_list) next;
	struct vdpa_priv *priv;
};

TAILQ_HEAD(vdpa_priv_list_head, priv_list);
static struct vdpa_priv_list_head priv_list =
					TAILQ_HEAD_INITIALIZER(priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct vdpa_priv_list *
find_priv_resource_by_did(int did)
{
    int found = 0;
    struct vdpa_priv_list *list;

    pthread_mutex_lock(&priv_list_lock);
    TAILQ_FOREACH(list, &priv_list, next) {
        if (did == list->priv->id) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&priv_list_lock);
    if (!found)
        return NULL;
    return list;
}

static int
mlx5_vdpa_get_queue_num(int did, uint32_t *queue_num)
{
    struct vdpa_priv_list *list_elem;

    list_elem = find_priv_resource_by_did(did);
    if (list_elem == NULL) {
        DRV_LOG(ERR, "Invalid device id: %d", did);
        return -1;
    }
    *queue_num = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
    return 0;
}

static int
mlx5_vdpa_get_vdpa_features(int did, uint64_t *features)
{
	struct vdpa_priv_list *list_elem;

	list_elem = find_priv_resource_by_did(did);
	if (list_elem == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	*features = MLX5_VDPA_FEATURES;
	return 0;
}

static int
mlx5_vdpa_get_protocol_features(int did, uint64_t *features)
{
	struct vdpa_priv_list *list_elem;

	list_elem = find_priv_resource_by_did(did);
	if (list_elem == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	*features = MLX5_VDPA_PROTOCOL_FEATURES;
	return 0;
}

//static int
//mlx5_vdpa_query_virtio_caps(struct vdpa_priv *priv __rte_unused)
//{
//	uint32_t in[MLX5_ST_SZ_DW(query_hca_cap_in)] = {0};
//	uint32_t out[MLX5_ST_SZ_DW(query_hca_cap_out)] = {0};
//	uint32_t in_special[MLX5_ST_SZ_DW(query_special_contexts_in)] = {0};
//	uint32_t out_special[MLX5_ST_SZ_DW(query_special_contexts_out)] = {0};
//	uint8_t dump_mkey_reported = 0;
//
//	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
//	MLX5_SET(query_hca_cap_in, in, op_mod,
//			(MLX5_HCA_CAP_GENERAL << 1) |
//			(MLX5_HCA_CAP_OPMOD_GET_CUR & 0x1));
//	if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in, sizeof(in),
//                                       out, sizeof(out))) {
//	    DRV_LOG(DEBUG, "Failed to Query Current HCA CAP section\n");
//	    return -1;
//	}
//	dump_mkey_reported = MLX5_GET(cmd_hca_cap,
//				      MLX5_ADDR_OF(query_hca_cap_out, out,
//					           capability),
//				      dump_fill_mkey);
//	if (!dump_mkey_reported) {
//	    DRV_LOG(DEBUG, "dump_fill_mkey is not supported\n");
//	    return -1;
//	}
//	/* Query the actual dump key. */
//	MLX5_SET(query_special_contexts_in, in_special, opcode,
//		 MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS);
//	if (mlx5_glue->dv_devx_general_cmd(priv->ctx, in_special, sizeof(in_special),
//                                       out_special, sizeof(out_special))) {
//	    DRV_LOG(DEBUG, "Failed to Query Special Contexts\n");
//		return -1;
//	}
//	priv->caps.dump_mkey = MLX5_GET(query_special_contexts_out,
//					out_special,
//					dump_fill_mkey);
//	/*
//	 * TODO (idos): Take from QUERY HCA CAP Device Emulation Capabilities.
//	 * For now only set protocol features support
//	 */
//	priv->caps.max_num_virtqs = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
//	/*
//	 * TODO (shahafs): Take from QUERY HCA CAP Device Emulation Capabilities.
//	 * For now only set protocol features support
//	 */
//	priv->caps.notify_stride = MLX5_VDPA_SW_NOTIFY_STRIDE;
//	priv->caps.virtio_net_features = MLX5_VDPA_FEATURES;
//	priv->caps.virtio_protocol_features = MLX5_VDPA_PROTOCOL_FEATURES;
//	DRV_LOG(DEBUG, "Virtio Caps:");
//	DRV_LOG(DEBUG, "	dump_mkey=0x%x ", priv->caps.dump_mkey);
//	DRV_LOG(DEBUG, "	max_num_virtqs=0x%x ", priv->caps.max_num_virtqs);
//	DRV_LOG(DEBUG, "	features_bits=0x%" PRIx64, priv->caps.virtio_net_features);
//	return 0;
//}

//#define MLX5_IB_MMAP_CMD_SHIFT 8
//#define MLX5_IB_MMAP_CMD_MASK ((1 << MLX5_IB_MMAP_CMD_SHIFT) - 1)
//#define MLX5_IB_CMD_SIZE 8
//#define MLX5_IB_MMAP_VIRTIO_NOTIFY 9
//static inline int
//mlx5_vdpa_get_notify_offset(uint16_t offset)
//{
//	uint16_t ext_offset = MLX5_IB_MMAP_CMD_SHIFT + MLX5_IB_CMD_SIZE;
//	return (((offset >> MLX5_IB_MMAP_CMD_SHIFT) << ext_offset) |
//		(MLX5_IB_MMAP_VIRTIO_NOTIFY << MLX5_IB_MMAP_CMD_SHIFT) |
//		(offset & MLX5_IB_MMAP_CMD_MASK));
//}

static int
mlx5_vdpa_report_notify_area(int vid, int qid __rte_unused, uint64_t *offset,
			     uint64_t *size)
{
	int dev_id;
	struct vdpa_priv_list *list;
	void * addr;

	dev_id = rte_vhost_get_vdpa_device_id(vid);
	if (dev_id < 0)
		goto error;
	list = find_priv_resource_by_did(dev_id);
	if (!list)
		goto error;
	*offset = 0x1000;
	*offset = *offset * 4096;
	*size = 0x1000;
	DRV_LOG(DEBUG, "Notify offset is 0x%" PRIx64 " size is %" PRId64,
		*offset, *size);
	addr = mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_SHARED, list->priv->pdev->intr_handle.vfio_dev_fd,
		    *offset);
	*((uint32_t *)addr + 1) =0x51;
	return 0;
error:
	DRV_LOG(DEBUG, "Invliad vDPA device id %d", vid);
	return -1;
}

static int
mlx5_vdpa_get_device_fd(int vid)
{
	int dev_id;
	struct vdpa_priv_list *list;

	dev_id = rte_vhost_get_vdpa_device_id(vid);
	if (dev_id < 0)
		goto error;
	list = find_priv_resource_by_did(dev_id);
	if (!list)
		goto error;
	return list->priv->pdev->intr_handle.vfio_dev_fd;
error:
	DRV_LOG(DEBUG, "Invliad vDPA device id %d", vid);
	return -1;
}

static struct rte_vdpa_dev_ops mlx5_vdpa_ops = {
	.get_queue_num = mlx5_vdpa_get_queue_num,
	.get_features = mlx5_vdpa_get_vdpa_features,
	.get_protocol_features = mlx5_vdpa_get_protocol_features,
	.dev_conf = NULL,
	.dev_close = NULL,
	.set_vring_state = NULL,
	.set_features = NULL,
	.migration_done = NULL,
	.get_vfio_group_fd = NULL,
	.get_vfio_device_fd = mlx5_vdpa_get_device_fd,
	.get_notify_area = mlx5_vdpa_report_notify_area,
};


//struct mlx5_vdpa_cmd {
//	struct mlx5_cmdq_entry	entry;
//	uint8_t			rsvd0[2048 - sizeof(struct mlx5_cmdq_entry)];
//	struct mlx5_cmd_block	ibox;
//	uint8_t			rsvd1[1024 - sizeof(struct mlx5_cmd_block)];
//	struct mlx5_cmd_block	obox;
//	uint8_t			rsvd2[1024 - sizeof(struct mlx5_cmd_block)];
//};

/**
 * DPDK callback to register a PCI device.
 *
 * This function spawns vdpa device out of a given PCI device.
 *
 * @param[in] pci_drv
 *   PCI driver structure (mlx5_vpda_driver).
 * @param[in] pci_dev
 *   PCI device information.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
#define MLX5_VDPA_READ_16_BE(a)	rte_be_to_cpu_16(rte_read16(a))
#define MLX5_VDPA_WRITE_32_BE(val, a) rte_write32(rte_cpu_to_be_32(val), a)
#define MLX5_VDPA_CPU_TO_BE_64(x) rte_cpu_to_be_64(x)
static int
mlx5_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev)
{
	struct vdpa_priv *priv = NULL;
	struct vdpa_priv_list *priv_list_elem = NULL;
//	int ret;

	assert(pci_drv == &mlx5_vdpa_driver);
	priv = rte_zmalloc("vDPA device private", sizeof(*priv),
			   RTE_CACHE_LINE_SIZE);
	priv_list_elem = rte_zmalloc("vDPA device priv list elem",
				     sizeof(*priv_list_elem),
				     RTE_CACHE_LINE_SIZE);
	if (!priv || !priv_list_elem) {
		DRV_LOG(DEBUG, "Unable to allocate memory for private structure");
		rte_errno = rte_errno ? rte_errno : ENOMEM;
		goto error;
	}
	priv->pdev = pci_dev;
	priv->dev_addr.pci_addr = pci_dev->addr;
	priv->dev_addr.type = PCI_ADDR;
	priv_list_elem->priv = priv;
	priv->id = rte_vdpa_register_device(&priv->dev_addr,
					     &mlx5_vdpa_ops);
	if (priv->id < 0) {
		DRV_LOG(DEBUG, "Unable to regsiter vDPA device");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&priv_list, priv_list_elem, next);
	pthread_mutex_unlock(&priv_list_lock);

//	mz = rte_memzone_reserve_aligned("vDPA command buffer", sizeof(*cmd), 0,
//			RTE_MEMZONE_IOVA_CONTIG, sizeof(*cmd));
//	memset(mz->addr, 0, sizeof(*cmd));
//	cmd.entry_type = 0x7;
//	cmd.entry.iptr = MLX_VDPA_CPU_TO_BE_64(mz->iova + 2048);
//	cmd.entry.optr = MLX_VDPA_CPU_TO_BE_64(mz->iova + 2048 + 1024);
//	iseg = (struct mlx5_iseg *)pci_dev->mem_resource[0].addr;
//	if (MLX5_VDPA_READ_16_BE(iseg->cmdif_rev) != 5)
//		goto error;
//	MLX5_VDPA_WRITE_32_BE((uint32_t)(mz->iova >> 32), &iseg->cmdq_pa_h);
//	MLX5_VDPA_WRITE_32_BE((uint32_t)(mz->iova), &iseg->cmdq_pa_l_sz);
//	while (MLX5_VDPA_READ_32_BE(&iseg->initializing) >> 31)
//		;
//						;
	return 0;

error:
	if (priv)
		rte_free(priv);
	if (priv_list_elem)
		rte_free(priv_list_elem);
	return -rte_errno;
}

/**
 * DPDK callback to remove a PCI device.
 *
 * This function removes all Ethernet devices belong to a given PCI device.
 *
 * @param[in] pci_dev
 *   Pointer to the PCI device.
 *
 * @return
 *   0 on success, the function cannot fail.
 */
static int
mlx5_vdpa_pci_remove(struct rte_pci_device *pci_dev __rte_unused)
{
	return 0;
}

static const struct rte_pci_id mlx5_vdpa_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BFVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BF)
	},

	{
		.vendor_id = 0
	}
};

static struct rte_pci_driver mlx5_vdpa_driver = {
	.driver = {
		.name = "net_mlx5_vdpa",
	},
	.id_table = mlx5_vdpa_pci_id_map,
	.probe = mlx5_vdpa_pci_probe,
	.remove = mlx5_vdpa_pci_remove,
	.drv_flags = 0,
};

#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS

/**
 * Suffix RTE_EAL_PMD_PATH with "-glue".
 *
 * This function performs a sanity check on RTE_EAL_PMD_PATH before
 * suffixing its last component.
 *
 * @param buf[out]
 *   Output buffer, should be large enough otherwise NULL is returned.
 * @param size
 *   Size of @p out.
 *
 * @return
 *   Pointer to @p buf or @p NULL in case suffix cannot be appended.
 */
static char *
mlx5_glue_path(char *buf, size_t size)
{
	static const char *const bad[] = { "/", ".", "..", NULL };
	const char *path = RTE_EAL_PMD_PATH;
	size_t len = strlen(path);
	size_t off;
	int i;

	while (len && path[len - 1] == '/')
		--len;
	for (off = len; off && path[off - 1] != '/'; --off)
		;
	for (i = 0; bad[i]; ++i)
		if (!strncmp(path + off, bad[i], (int)(len - off)))
			goto error;
	i = snprintf(buf, size, "%.*s-glue", (int)len, path);
	if (i == -1 || (size_t)i >= size)
		goto error;
	return buf;
error:
	DRV_LOG(ERR,
		"unable to append \"-glue\" to last component of"
		" RTE_EAL_PMD_PATH (\"" RTE_EAL_PMD_PATH "\"),"
		" please re-configure DPDK");
	return NULL;
}

/**
 * Initialization routine for run-time dependency on rdma-core.
 */
static int
mlx5_glue_init(void)
{
	/*
	 * TODO (shahaf): move it to shared location and make sure glue lib init only once.
	 */
	char glue_path[sizeof(RTE_EAL_PMD_PATH) - 1 + sizeof("-glue")];
	const char *path[] = {
		/*
		 * A basic security check is necessary before trusting
		 * MLX5_GLUE_PATH, which may override RTE_EAL_PMD_PATH.
		 */
		(geteuid() == getuid() && getegid() == getgid() ?
		 getenv("MLX5_GLUE_PATH") : NULL),
		/*
		 * When RTE_EAL_PMD_PATH is set, use its glue-suffixed
		 * variant, otherwise let dlopen() look up libraries on its
		 * own.
		 */
		(*RTE_EAL_PMD_PATH ?
		 mlx5_glue_path(glue_path, sizeof(glue_path)) : ""),
	};
	unsigned int i = 0;
	void *handle = NULL;
	void **sym;
	const char *dlmsg;

	while (!handle && i != RTE_DIM(path)) {
		const char *end;
		size_t len;
		int ret;

		if (!path[i]) {
			++i;
			continue;
		}
		end = strpbrk(path[i], ":;");
		if (!end)
			end = path[i] + strlen(path[i]);
		len = end - path[i];
		ret = 0;
		do {
			char name[ret + 1];

			ret = snprintf(name, sizeof(name), "%.*s%s" MLX5_GLUE,
				       (int)len, path[i],
				       (!len || *(end - 1) == '/') ? "" : "/");
			if (ret == -1)
				break;
			if (sizeof(name) != (size_t)ret + 1)
				continue;
			DRV_LOG(DEBUG, "looking for rdma-core glue as \"%s\"",
				name);
			handle = dlopen(name, RTLD_LAZY);
			break;
		} while (1);
		path[i] = end + 1;
		if (!*end)
			++i;
	}
	if (!handle) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(WARNING, "cannot load glue library: %s", dlmsg);
		goto glue_error;
	}
	sym = dlsym(handle, "mlx5_glue");
	if (!sym || !*sym) {
		rte_errno = EINVAL;
		dlmsg = dlerror();
		if (dlmsg)
			DRV_LOG(ERR, "cannot resolve glue symbol: %s", dlmsg);
		goto glue_error;
	}
	mlx5_glue = *sym;
	return 0;
glue_error:
	if (handle)
		dlclose(handle);
	DRV_LOG(WARNING,
		"cannot initialize PMD due to missing run-time dependency on"
		" rdma-core libraries (libibverbs, libmlx5)");
	return -rte_errno;
}

#endif
/**
 * Driver initialization routine.
 */
RTE_INIT(rte_mlx5_vdpa_init)
{
	/* Initialize driver log type. */
	mlx5_vdpa_logtype = rte_log_register("pmd.net.mlx5_vdpa");
	if (mlx5_vdpa_logtype >= 0)
		rte_log_set_level(mlx5_vdpa_logtype, RTE_LOG_NOTICE);

	/*
	 * RDMAV_HUGEPAGES_SAFE tells ibv_fork_init() we intend to use
	 * huge pages. Calling ibv_fork_init() during init allows
	 * applications to use fork() safely for purposes other than
	 * using this PMD, which is not supported in forked processes.
	 */
	setenv("RDMAV_HUGEPAGES_SAFE", "1", 1);
#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS
	if (mlx5_glue_init())
		return;
	assert(mlx5_glue);
#endif
#ifndef NDEBUG
	/* Glue structure must not contain any NULL pointers. */
	{
		unsigned int i;

		for (i = 0; i != sizeof(*mlx5_glue) / sizeof(void *); ++i)
			assert(((const void *const *)mlx5_glue)[i]);
	}
#endif
	if (strcmp(mlx5_glue->version, MLX5_GLUE_VERSION)) {
		DRV_LOG(ERR,
			"rdma-core glue \"%s\" mismatch: \"%s\" is required",
			mlx5_glue->version, MLX5_GLUE_VERSION);
		return;
	}
	mlx5_glue->fork_init();
	rte_pci_register(&mlx5_vdpa_driver);
}

RTE_PMD_EXPORT_NAME(net_mlx5_vdpa, __COUNTER__);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5_vdpa, mlx5_vdpa_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5_vdpa, "* ib_uverbs & mlx5_core & mlx5_ib");
