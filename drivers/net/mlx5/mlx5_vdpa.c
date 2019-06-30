/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <linux/virtio_net.h>

#include <unistd.h>
#include <dlfcn.h>
#include <rte_bus_pci.h>
#include <rte_errno.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_malloc.h>
#include <rte_common.h>

#include "mlx5.h"
#include "mlx5_defs.h"
#include "mlx5_utils.h"
#include "mdev_lib.h"
#include "mlx5_prm.h"

/*
 * TODO: check if allready exists on latest upstream and if so remove.
 */
#ifndef VIRTIO_F_ORDER_PLATFORM
#define VIRTIO_F_ORDER_PLATFORM 36
#endif

#ifndef NOMINMAX
#ifndef max
#define max(a, b)            (((a) > (b)) ? (a) : (b))
#endif
#endif  /* NOMINMAX */

#define MKEY_VARIANT_PART 0x50

/*
 * Driver Static values in the absence of device VIRTIO emulation support
 * TODO(idos): Remove this when query virtio_net capabilities is supported
 * Please keep this a power of 2 value.
 */
#define MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED 16

#define MLX5_VDPA_FEATURES ((1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
			    (1ULL << VIRTIO_F_VERSION_1) | \
			    (1ULL << VIRTIO_F_ANY_LAYOUT) | \
			    (1ULL << VIRTIO_NET_F_MQ ) | \
			    (1ULL << VIRTIO_F_ORDER_PLATFORM))

#define MLX5_VDPA_PROTOCOL_FEATURES \
			    ((1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER) | \
			     (1ULL << VHOST_USER_PROTOCOL_F_MQ))

/** Driver-specific log messages type. */
int mlx5_vdpa_logtype;

uint8_t mlx5_vdpa_rss_hash_default_key[] = {
	0x2c, 0xc6, 0x81, 0xd1,
	0x5b, 0xdb, 0xf4, 0xf7,
	0xfc, 0xa2, 0x83, 0x19,
	0xdb, 0x1a, 0x3e, 0x94,
	0x6b, 0x9e, 0x38, 0xd9,
	0x2c, 0x9c, 0x03, 0xd1,
	0xad, 0x99, 0x44, 0xa7,
	0xd9, 0x56, 0x3d, 0x59,
	0x06, 0x3c, 0x25, 0xf3,
	0xfc, 0x1f, 0xdc, 0x2a,
};

struct mlx5_vdpa_caps {
	uint32_t dump_mkey;
	uint16_t max_num_virtqs;
	uint64_t virtio_net_features;
	uint64_t virtio_protocol_features;
};

struct virtq_info {
	uint32_t virtq_id;
	uint32_t umem_id;
	void *umem_buf;
};

struct mlx5_vdpa_steer_info {
	uint32_t tirn;
	uint32_t rqtn;
	uint32_t ftn;
	uint32_t fgn;
};

struct mlx5_vdpa_relay_thread {
	int       epfd; /* Epoll fd for relay thread. */
	pthread_t tid; /* Notify thread id. */
	void      *notify_base; /* Notify base address. */
};

struct mlx5_devx_mkey_attr {
	uint64_t        addr;
	uint64_t        size;
	uint32_t        pas_id;
	uint32_t        pd;
	uint32_t        log_entity_size;
	uint32_t        translations_octword_size;
};

struct mlx5_klm {
	uint32_t byte_count;
	uint32_t mkey;
	uint64_t address;
};

struct mlx5_vdpa_query_mr {
	void			*addr;
	uint64_t		length;
	uint32_t                umem_id;
	uint32_t                mkey_ix;
	int			is_indirect;
};

struct mlx5_vdpa_query_mr_list {
	SLIST_ENTRY(mlx5_vdpa_query_mr_list) next;
	struct mlx5_vdpa_query_mr *vdpa_query_mr;
};

struct vdpa_priv {
	int                           id; /* vDPA device id. */
	int                           vid; /* virtio_net driver id */
	int                           vfio_container_fd;
	int                           vfio_group_fd;
	int                           vfio_dev_fd;
	uint16_t                      uid;
	uint32_t                      pdn;
	uint32_t                      tisn;
	uint32_t                      gpa_mkey_index;
	uint16_t                      nr_vring;
	rte_atomic32_t                dev_attached;
	struct rte_pci_device         *pdev;
	void			      *base_addr;
	struct mlx5_mdev_context      *mctx;
	struct rte_vdpa_dev_addr      dev_addr;
	struct mlx5_vdpa_caps         caps;
	struct mlx5_vdpa_relay_thread relay;
	struct mlx5_vdpa_steer_info   rx_steer_info;
	struct virtq_info virtq[MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2];
	SLIST_HEAD(mr_list, mlx5_vdpa_query_mr_list) mr_list;
};

struct vdpa_priv_list {
	TAILQ_ENTRY(vdpa_priv_list) next;
	struct vdpa_priv           *priv;
};

TAILQ_HEAD(vdpa_priv_list_head, priv_list);
static struct vdpa_priv_list_head priv_list =
					TAILQ_HEAD_INITIALIZER(priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

static inline struct mlx5_mdev_memzone* mlx5_vdpa_vfio_dma(void *owner,
							   const char *name,
							   size_t size,
							   size_t align)
{
	struct vdpa_priv *priv = owner;
	int mdev_sz = sizeof(struct mlx5_mdev_memzone);
	struct mlx5_mdev_memzone *mz = rte_zmalloc("mdev", mdev_sz, 64);
	void *va = rte_zmalloc(name, size, align);
	/*
	 * Since VFIO DMA MAP API requires the user to supply the IOVA,
	 * we'll be using identity mapping (va==iova) since this PMD is
	 * only application running on the function.
	 * TODO(idos): Change to global IOVA address space per function
	 *
	 */
	uint64_t iova = (uint64_t)va;
	rte_vfio_container_dma_map(priv->vfio_container_fd,
				   (uint64_t)va, iova, size);
	if(!mz)
		return mz;
	mz->addr = va;
	mz->phys_addr = iova;
	return mz;
}

static int create_uctx(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_uctx_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_uctx_out)] = {0};
	void *uctx;
	int err;

	MLX5_SET(create_uctx_in, in, opcode, MLX5_CMD_OP_CREATE_UCTX);
	uctx = MLX5_ADDR_OF(create_uctx_in, in, uctx);
	MLX5_SET(uctx, uctx, cap, MLX5_UCTX_CAP_RAW_TX);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_uctx_out, out, status)) {
		DRV_LOG(ERR, "UCTX allocation failure");
		return -1;
	}
	priv->uid = MLX5_GET(create_uctx_out, out, uid);
	DRV_LOG(DEBUG, "Success creating PD 0x%x", priv->uid);
	return 0;
}

static int create_pd(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(alloc_pd_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(alloc_pd_out)] = {0};
	int err;

	MLX5_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	MLX5_SET(alloc_pd_in, in, uid, priv->uid);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(alloc_pd_out, out, status)) {
		DRV_LOG(ERR, "PD allocation failure");
		return -1;
	}
	priv->pdn = MLX5_GET(alloc_pd_out, out, pd);
	DRV_LOG(DEBUG, "Success creating PD 0x%x", priv->pdn);
	return 0;
}

/*
 * According to VIRTIO_NET Spec the virtqueues index identity its type by:
 * 0 receiveq1
 * 1 transmitq1
 * ...
 * 2(N-1) receiveqN
 * 2(N-1)+1 transmitqN
 * 2N controlq
 */
static bool is_virtq_recvq(int virtq_index, int nr_vring)
{
	if (virtq_index % 2 == 0 && virtq_index != nr_vring - 1)
		return true;
	return false;
}

static int create_rqt(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_rqt_in) +
		    (MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED *
		     MLX5_ST_SZ_DW(rq_num))] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_rqt_out)] = {0};
	void *rqtc = NULL;
	int err;
	int i;
	int j = 0;

	MLX5_SET(create_rqt_in, in, opcode, MLX5_CMD_OP_CREATE_RQT);
	MLX5_SET(create_rqt_in, in, uid, priv->uid);
	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);
	MLX5_SET(rqtc, rqtc, list_q_type, MLX5_INLINE_Q_TYPE_VIRTQ);
	MLX5_SET(rqtc, rqtc, rqt_max_size, MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED);
	for (i = 0; i < priv->nr_vring; i++) {
		if (is_virtq_recvq(i, priv->nr_vring)) {
			MLX5_SET(rqtc, rqtc, rq_num[j],
				 priv->virtq[i].virtq_id);
			j++;
		}
	}
	MLX5_SET(rqtc, rqtc, rqt_actual_size, j);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_rqt_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create RQT");
		return -1;
	}
	priv->rx_steer_info.rqtn = MLX5_GET(create_rqt_out, out, rqtn);
	DRV_LOG(DEBUG, "Success creating RQT 0x%x", priv->rx_steer_info.rqtn);
	return 0;
}

#define MLX5_HASH_IP_L4PORTS (MLX5_HASH_FIELD_SEL_SRC_IP   |\
			      MLX5_HASH_FIELD_SEL_DST_IP   |\
			      MLX5_HASH_FIELD_SEL_L4_SPORT |\
			      MLX5_HASH_FIELD_SEL_L4_DPORT)

static int create_tir(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_tir_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_tir_out)] = {0};
	void *rss_key = NULL;
	void *tirc = NULL;
	void *hfso = NULL;
	size_t len;
	int err;

	MLX5_SET(create_tir_in, in, opcode, MLX5_CMD_OP_CREATE_TIR);
	MLX5_SET(create_tir_in, in, uid, priv->uid);
	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
	MLX5_SET(tirc, tirc, indirect_table, priv->rx_steer_info.rqtn);
	MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_RX_HASH_FN_TOEPLITZ);
	rss_key = MLX5_ADDR_OF(tirc, tirc, rx_hash_toeplitz_key);
	len = MLX5_FLD_SZ_BYTES(tirc, rx_hash_toeplitz_key);
	MLX5_SET(tirc, tirc, rx_hash_symmetric, 1);
	memcpy(rss_key, mlx5_vdpa_rss_hash_default_key, len);
	hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);
	MLX5_SET(rx_hash_field_select, hfso, l3_prot_type, MLX5_L3_PROT_TYPE_IPV4);
	MLX5_SET(rx_hash_field_select, hfso, l4_prot_type, MLX5_L4_PROT_TYPE_UDP);
	MLX5_SET(rx_hash_field_select, hfso, selected_fields, MLX5_HASH_IP_L4PORTS);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_tir_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create TIR");
		return -1;
	}
	priv->rx_steer_info.tirn = MLX5_GET(create_tir_out, out, tirn);
	DRV_LOG(DEBUG, "Success creating TIR 0x%x", priv->rx_steer_info.tirn);
	return 0;
}

static int mlx5_vdpa_create_flow_table(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_flow_table_in)]   = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_flow_table_out)] = {0};
	int err;

	MLX5_SET(create_flow_table_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_TABLE);
	MLX5_SET(create_flow_table_in, in, uid, priv->uid);
	MLX5_SET(create_flow_table_in, in, table_type,
		 MLX5_FLOW_TABLE_TYPE_NIC_RX);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_flow_table_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create FLOW Table");
		return -1;
	}
	priv->rx_steer_info.ftn = MLX5_GET(create_flow_table_out, out, table_id);
	return 0;
}

static int mlx5_vdpa_create_flow_group(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_flow_group_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_flow_group_out)] = {0};
	int err;

	MLX5_SET(create_flow_group_in, in, opcode,
		 MLX5_CMD_OP_CREATE_FLOW_GROUP);
	MLX5_SET(create_flow_group_in, in, uid, priv->uid);
	MLX5_SET(create_flow_group_in, in, table_id, priv->rx_steer_info.ftn);
	MLX5_SET(create_flow_group_in, in, table_type,
		 MLX5_FLOW_TABLE_TYPE_NIC_RX);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_flow_group_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create FLOW Table");
		return -1;
	}
	priv->rx_steer_info.fgn = MLX5_GET(create_flow_group_out, out,
					   group_id);
	return 0;
}

static int mlx5_vdpa_set_promisc_fte(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(set_fte_in) +
		    sizeof(struct mlx5_ifc_dest_format_struct_bits)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(set_fte_out)] = {0};
	void *flowc;
	void *dst;
	int err;

	MLX5_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	MLX5_SET(set_fte_in, in, uid, priv->uid);
	MLX5_SET(set_fte_in, in, table_id, priv->rx_steer_info.ftn);
	MLX5_SET(set_fte_in, in, table_type, MLX5_FLOW_TABLE_TYPE_NIC_RX);
	flowc = MLX5_ADDR_OF(set_fte_in, in, flowc);
	MLX5_SET(flow_context, flowc, group_id, priv->rx_steer_info.fgn);
	MLX5_SET(flow_context, flowc, flow_tag, 0x1);
	MLX5_SET(flow_context, flowc, action,
		 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);
	MLX5_SET(flow_context, flowc, destination_list_size, 1);
	dst = MLX5_ADDR_OF(flow_context, flowc, destination);
	MLX5_SET(dest_format_struct, dst, destination_type,
		 MLX5_FLOW_DESTINATION_TYPE_TIR);
	MLX5_SET(dest_format_struct, dst, destination_id,
		 priv->rx_steer_info.tirn);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(set_fte_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create FLOW Table");
		return -1;
	}
	return 0;
}

static int mlx5_vdpa_set_flow_table_root(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(set_flow_table_root_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(set_flow_table_root_out)] = {0};
	int err;

	MLX5_SET(set_flow_table_root_in, in, opcode,
		 MLX5_CMD_OP_SET_FLOW_TABLE_ROOT);
	MLX5_SET(set_flow_table_root_in, in, uid, priv->uid);
	MLX5_SET(set_flow_table_root_in, in, table_type,
		 MLX5_FLOW_TABLE_TYPE_NIC_RX);
	MLX5_SET(set_flow_table_root_in, in, table_id,
		 priv->rx_steer_info.ftn);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(set_flow_table_root_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create FLOW Table");
		return -1;
	}
	return 0;
}

static int mlx5_vdpa_enable_promisc(struct vdpa_priv *priv)
{
	if (mlx5_vdpa_create_flow_table(priv))
		goto ft_err;
	if (mlx5_vdpa_create_flow_group(priv))
		goto ft_err;
	if (mlx5_vdpa_set_promisc_fte(priv))
		goto ft_err;
	if (mlx5_vdpa_set_flow_table_root(priv))
		goto ft_err;
	DRV_LOG(DEBUG, "Success creating Promiscuous flow rule");
	return 0;
ft_err:
	DRV_LOG(DEBUG, "Failure in creating Promiscuous steering");
	return -1;
}

/* TODO(idos): Move this to a shared location with ifcvf_vdpa driver */
static uint64_t hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	uint32_t i;
	uint64_t gpa = 0;

	if (rte_vhost_get_mem_table(vid, &mem) < 0)
		goto exit;
	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];
		if (hva >= reg->host_user_addr &&
		    hva < reg->host_user_addr + reg->size) {
			gpa = hva - reg->host_user_addr + reg->guest_phys_addr;
			break;
		}
	}
exit:
	if (mem)
		free(mem);
	return gpa;
}

static int
mlx5_vdpa_create_umem(struct vdpa_priv *priv, uint64_t umem_size,
		      uint64_t iova, uint32_t *umem_id)
{
	uint8_t in[MLX5_ST_SZ_DB(create_umem_in) +
		   sizeof(struct mlx5_ifc_mtt_entry_bits)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_umem_out)] = {0};
	void *umemc;
	void *mtt;
	int err;

	MLX5_SET(create_umem_in, in, opcode, MLX5_CMD_OP_CREATE_UMEM);
	MLX5_SET(create_umem_in, in, uid, priv->uid);
	umemc = MLX5_ADDR_OF(create_umem_in, in, umem_context);
	/*
	 * Important: This function assumes the buffer represented by
	 * iova and umem_size is contiguous (in IOVA space), a valid
	 * natural page size (e.g natural power of 2 number, greater
	 * than 4KB) and naturally aligned.
	 *
	 * */
	MLX5_SET(umemc, umemc, log_page_size, (rte_log2_u32(umem_size) >> 12));
	MLX5_SET64(umemc, umemc, num_of_mtt, 1);
	MLX5_SET(umemc, umemc, page_offset, 0);
	mtt = MLX5_ADDR_OF(umemc, umemc, mtt);
	MLX5_SET64(mtt_entry, mtt, ptag, iova);
	MLX5_SET(mtt_entry, mtt, wr_en, 1);
	MLX5_SET(mtt_entry, mtt, rd_en, 1);

	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_umem_out, out, status)) {
		DRV_LOG(DEBUG, "Failed to create UMEM");
		return -1;
	}

	*umem_id = MLX5_GET(create_umem_out, out, umem_id);
	return 0;
}

#define MLX5_VDPA_VIRTIO_NET_Q_UMEM_SIZE (128 * 1024)

static int
create_split_virtq(struct vdpa_priv *priv, int index,
		   struct rte_vhost_vring *vq)
{
	uint32_t in[MLX5_ST_SZ_DW(create_virtq_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	struct mlx5_mdev_memzone *umem_mz = NULL;
	void *virtq = NULL;
	void *hdr = NULL;
	struct virtq_info *info = &priv->virtq[index];
	uint64_t gpa;
	int umem_size;
	int err;

	/* Setup UMEM for this virt queue. */
	umem_size = MLX5_VDPA_VIRTIO_NET_Q_UMEM_SIZE;
	umem_mz = mlx5_vdpa_vfio_dma(priv, "virtq_umem", umem_size, umem_size);
	if (!umem_mz) {
		DRV_LOG(ERR, "Error allocating memory for Virt queue");
		return -1;
	}
	if (mlx5_vdpa_create_umem(priv, umem_size, umem_mz->phys_addr,
				 &info->umem_id)) {
		DRV_LOG(ERR, "Error creating UMEM for Virt queue");
		return -1;
	}
	/* Fill command mailbox. */
	hdr = MLX5_ADDR_OF(create_virtq_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr, hdr, opcode,
		 MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr, in, uid, priv->uid);
	MLX5_SET(general_obj_in_cmd_hdr, hdr, obj_type, MLX5_OBJ_TYPE_VIRTQ);
	virtq = MLX5_ADDR_OF(create_virtq_in, in, virtq);
	if (is_virtq_recvq(index, priv->nr_vring)) {
		MLX5_SET(virtq, virtq, virtio_direction,
			 MLX5_VIRTQ_OBJ_QUEUE_TYPE_RX);
	} else {
		MLX5_SET(virtq, virtq, virtio_direction,
			 MLX5_VIRTQ_OBJ_QUEUE_TYPE_TX);
	}
	gpa = hva_to_gpa(priv->vid, (uint64_t)(uintptr_t)vq->desc);
	if (!gpa) {
		DRV_LOG(ERR, "Fail to get GPA for descriptor ring");
		return -1;
	}
	MLX5_SET64(virtq, virtq, desc_addr, gpa);
	gpa = hva_to_gpa(priv->vid, (uint64_t)(uintptr_t)vq->used);
	if (!gpa) {
		DRV_LOG(ERR, "Fail to get GPA for used ring");
		return -1;
	}
	MLX5_SET64(virtq, virtq, used_addr, gpa);
	gpa = hva_to_gpa(priv->vid, (uint64_t)(uintptr_t)vq->avail);
	if (!gpa) {
		DRV_LOG(ERR, "Fail to get GPA for available ring");
		return -1;
	}
	MLX5_SET64(virtq, virtq, available_addr, gpa);
	MLX5_SET16(virtq, virtq, queue_size, vq->size);
	MLX5_SET(virtq, virtq, data_mkey, priv->gpa_mkey_index);
	/*
	 * For now we use the same gpa mkey for both ctrl and data
	 * TODO(idos): When Live migration support is added, need
	 * to create another hva-based mkey and modify the virtq
	 * ctrl_mkey field to it.
	 */
	MLX5_SET(virtq, virtq, ctrl_mkey, priv->gpa_mkey_index);
	MLX5_SET(virtq, virtq, umem_id, info->umem_id);
	MLX5_SET(virtq, virtq, tisn, priv->tisn);
	MLX5_SET(virtq, virtq, doorbell_stride_idx, index);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(general_obj_out_cmd_hdr, out, status)) {
		DRV_LOG(DEBUG, "Failed to create VIRTQ General Obj DEVX");
		return -1;
	}
	info->virtq_id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);
	DRV_LOG(DEBUG, "Success creating VIRTQ 0x%x", info->virtq_id);
	return 0;
}

static int mlx5_vdpa_setup_rx_steering(struct vdpa_priv *priv)
{
	if (create_rqt(priv)) {
		DRV_LOG(ERR, "Create Indirection table failed");
		return -1;
	}
	if (create_tir(priv)) {
		DRV_LOG(ERR, "Create TIR failed");
		return -1;
	}
	if (mlx5_vdpa_enable_promisc(priv)) {
		DRV_LOG(ERR, "Promiscuous flow rule creation failed");
		return -1;
	}
	return 0;
}

static int mlx5_vdpa_setup_virtqs(struct vdpa_priv *priv)
{
	int i, nr_vring;
	struct rte_vhost_vring vq;

	nr_vring = rte_vhost_get_vring_num(priv->vid);
	priv->nr_vring = nr_vring;
	for (i = 0; i < nr_vring; i++) {
		rte_vhost_get_vhost_vring(priv->vid, i, &vq);
		if (create_split_virtq(priv, i, &vq)) {
			DRV_LOG(ERR, "Create VIRTQ general obj failed");
			/* TODO(idos): Remove and fail when FW supports */
			DRV_LOG(INFO, "Still no FW support, continuing..");
		}
	}
	if (mlx5_vdpa_setup_rx_steering(priv)) {
		DRV_LOG(ERR, "Create Steering for RX failed");
		/* TODO: Remove and fail when FW supports */
		DRV_LOG(INFO, "Still no FW support, continuing..");
	}
	return 0;
}

static int mlx5_vdpa_create_mkey(struct mlx5_mdev_context *ctx,
				 struct mlx5_devx_mkey_attr *mkey_attr,
				 uint16_t uid,
				 uint32_t *mkey_id)
{
	uint32_t in[MLX5_ST_SZ_DW(create_mkey_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t mkey_ix;
	void *mkc;
	int translations_oct_size = ((((mkey_attr->size + 4095) / 4096) + 1) / 2);
	int err;

	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	MLX5_SET(create_mkey_in, in, uid, uid);
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 0x1);
	MLX5_SET(mkc, mkc, lr, 0x1);
	MLX5_SET(mkc, mkc, rw, 0x1);
	MLX5_SET(mkc, mkc, rr, 0x1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, length64, 0x0);
	MLX5_SET(mkc, mkc, pd, mkey_attr->pd);
	MLX5_SET(mkc, mkc, mkey_7_0, MKEY_VARIANT_PART);//FIXME: should be dynamic
	MLX5_SET(mkc, mkc, translations_octword_size,translations_oct_size);
	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		translations_oct_size);
	MLX5_SET(create_mkey_in, in, pg_access, 1);
	MLX5_SET(create_mkey_in, in, mkey_umem_valid, 1);
	MLX5_SET64(mkc, mkc, start_addr, mkey_attr->addr);
	MLX5_SET64(mkc, mkc, len, mkey_attr->size);
	MLX5_SET(mkc, mkc, log_page_size, 12);
	MLX5_SET(create_mkey_in, in, mkey_umem_id, mkey_attr->pas_id);

	err = mlx5_mdev_cmd_exec(ctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_mkey_out, out, status)) {
		DRV_LOG(ERR, "Can't create mkey cmd");
		return -1;
	}
	mkey_ix = MLX5_GET(create_mkey_out, out, mkey_index);
	mkey_ix = (mkey_ix << 8) | MKEY_VARIANT_PART;
	*mkey_id = mkey_ix;
	DRV_LOG(DEBUG, "create mkey success value %d", mkey_ix);
	return 0;
}

static int mlx5_create_indirect_mkey(struct mlx5_mdev_context *ctx,
				     struct mlx5_devx_mkey_attr *mkey_attr,
				     struct mlx5_klm *klm_array, int num_klm,
				     uint16_t uid, uint32_t *mkey_id)
{
	int translations_oct_size = (((num_klm / 4) + (num_klm % 4)) * 4);
	uint32_t in_size = MLX5_ST_SZ_DB(create_mkey_in) +
				translations_oct_size * MLX5_ST_SZ_DB(klm);
	uint32_t *in = rte_zmalloc("in", in_size, 64);
	uint32_t out[MLX5_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t mkey_ix;
	void *mkc;
	uint8_t *klm = (uint8_t *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	int err;

	MLX5_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	MLX5_SET(create_mkey_in, in, uid, uid);
	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, lw, 0x1);
	MLX5_SET(mkc, mkc, lr, 0x1);
	MLX5_SET(mkc, mkc, rw, 0x1);
	MLX5_SET(mkc, mkc, rr, 0x1);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_KSM);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, length64, 0x0);
	MLX5_SET(mkc, mkc, pd, mkey_attr->pd);
	MLX5_SET(mkc, mkc, mkey_7_0, MKEY_VARIANT_PART);//FIXME: should be dynamic
	MLX5_SET(mkc, mkc, translations_octword_size, translations_oct_size);
	MLX5_SET(create_mkey_in, in,
		translations_octword_actual_size, translations_oct_size);
	MLX5_SET(create_mkey_in, in, pg_access, 0);
	MLX5_SET64(mkc, mkc, start_addr, mkey_attr->addr);
	MLX5_SET64(mkc, mkc, len, mkey_attr->size);
	MLX5_SET(mkc, mkc, log_page_size, max(mkey_attr->log_entity_size, 12));
	for (int i = 0; i < num_klm; i++) {
		MLX5_SET(klm, klm, mkey, klm_array[i].mkey);
		MLX5_SET64(klm, klm, address, klm_array[i].address);
		klm += MLX5_ST_SZ_DB(klm);
	}
	for (int i = num_klm; i < translations_oct_size; i++) {
		MLX5_SET(klm, klm, mkey, 0x0);
		MLX5_SET64(klm, klm, address, 0x0);
		klm += MLX5_ST_SZ_DB(klm);
	}
	err = mlx5_mdev_cmd_exec(ctx, in, in_size, out, sizeof(out));
	if (err || MLX5_GET(create_mkey_out, out, status)) {
		DRV_LOG(ERR, "Can't create mkey error %s", strerror(errno));
		return -1;
	}
	mkey_ix = MLX5_GET(create_mkey_out, out, mkey_index);
	mkey_ix = (mkey_ix << 8) | MKEY_VARIANT_PART;
	*mkey_id = mkey_ix;
	return 0;
}

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
	*queue_num = list_elem->priv->caps.max_num_virtqs;
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
	*features = list_elem->priv->caps.virtio_net_features;
	return 0;
}

static void
mlx5_vdpa_notify_queue(struct vdpa_priv *priv, int qid __rte_unused)
{
	/*
	 * Write must be 4B in length in order to pass the device PCI.
	 * need to further investigate the root cause.
	 */
	rte_write32(qid, priv->relay.notify_base);
}

static void *
mlx5_vdpa_notify_relay(void *arg)
{
	int i, kickfd, epfd, nfds = 0;
	uint32_t qid, q_num;
	struct epoll_event events[MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2];
	struct epoll_event ev;
	uint64_t buf;
	int nbytes;
	struct rte_vhost_vring vring;
	struct vdpa_priv *priv = (struct vdpa_priv *)arg;

	q_num = rte_vhost_get_vring_num(priv->id);
	epfd = epoll_create(MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED * 2);
	if (epfd < 0) {
		DRV_LOG(ERR, "failed to create epoll instance.");
		return NULL;
	}
	priv->relay.epfd = epfd;
	for (qid = 0; qid < q_num; qid++) {
		ev.events = EPOLLIN | EPOLLPRI;
		rte_vhost_get_vhost_vring(priv->id, qid, &vring);
		ev.data.u64 = qid | (uint64_t)vring.kickfd << 32;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, vring.kickfd, &ev) < 0) {
			DRV_LOG(ERR, "epoll add error: %s", strerror(errno));
			return NULL;
		}
	}
	for (;;) {
		nfds = epoll_wait(epfd, events, q_num, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			DRV_LOG(ERR, "epoll_wait return fail");
			return NULL;
		}
		for (i = 0; i < nfds; i++) {
			qid = events[i].data.u32;
			kickfd = (uint32_t)(events[i].data.u64 >> 32);
			do {
				nbytes = read(kickfd, &buf, 8);
				if (nbytes < 0) {
					if (errno == EINTR ||
					    errno == EWOULDBLOCK ||
					    errno == EAGAIN)
						continue;
					DRV_LOG(INFO, "Error reading "
						"kickfd: %s",
						strerror(errno));
				}
				break;
			} while (1);
			mlx5_vdpa_notify_queue(priv, qid);
		}
	}
	return NULL;
}

static int
mlx5_vdpa_setup_notify_relay(struct vdpa_priv *priv)
{
	void *addr;
	int ret;

	addr = (uint8_t *)(priv->base_addr) + 0x1000;
	priv->relay.notify_base = addr;
	/* TODO: enforce the thread affinity. */
	ret = pthread_create(&priv->relay.tid, NULL, mlx5_vdpa_notify_relay,
			     (void *)priv);
	if (ret) {
		DRV_LOG(ERR, "failed to create notify relay pthread.");
		return -1;
	}
	return 0;
}

static int
mlx5_vdpa_dma_map(struct vdpa_priv *priv)
{
	uint32_t i;
	int ret;
	struct rte_vhost_memory *mem = NULL;
	struct mlx5_devx_mkey_attr mkey_attr;
	static int klm_index;
	struct mlx5_vdpa_query_mr *entry = NULL;
	struct mlx5_vdpa_query_mr_list *list_elem = NULL;
	struct rte_vhost_mem_region *reg = NULL;
	/*TODO(liel): Working with KLM size of 1GB, change to GCD on empty_mr and region sizes*/
	uint64_t klm_size = 1073741824;
	uint64_t min_size = klm_size;
	uint64_t mem_size;

	SLIST_INIT(&priv->mr_list);
	ret = rte_vhost_get_mem_table(priv->id, &mem);
	if (ret < 0) {
		DRV_LOG(ERR, "failed to get VM memory layout.");
		return -1;
	}
	for (i = 0; i < (mem->nregions); i++) {
		if (min_size > mem->regions[i].size) {
			DRV_LOG(ERR, "Min region size is smaller than KLM size.");
			return -1;
		}
	}
	klm_index = 0;
	mem_size = (mem->regions[(mem->nregions - 1)].guest_phys_addr) +
				(mem->regions[(mem->nregions - 1)].size) -
				(mem->regions[0].guest_phys_addr);
	struct mlx5_klm klm_array[mem_size / klm_size];
	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];
		DRV_LOG(INFO, "region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);
		list_elem = rte_malloc(__func__, sizeof(*list_elem),
				RTE_CACHE_LINE_SIZE);
		entry =
		    rte_malloc(__func__, sizeof(*entry), RTE_CACHE_LINE_SIZE);
		if (!entry || !list_elem) {
			DRV_LOG(ERR, "Unable to allocate memory");
			goto error;
		}

		ret = rte_vfio_container_dma_map(priv->vfio_container_fd,
						 reg->host_user_addr,
						 reg->guest_phys_addr,
						 reg->size);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to VFIO DMA Map");
			goto error;
		}
		if (mlx5_vdpa_create_umem(priv, reg->size,
					  reg->guest_phys_addr,
					  &entry->umem_id)) {
			DRV_LOG(ERR, "Failed to create UMEM");
			goto error;
		}
		mkey_attr.addr = (uintptr_t)(reg->guest_phys_addr);
		mkey_attr.size = reg->size;
		mkey_attr.pas_id = entry->umem_id;
		mkey_attr.pd = priv->pdn;
		if (mlx5_vdpa_create_mkey(priv->mctx, &mkey_attr, priv->uid,
					  &entry->mkey_ix)) {
			DRV_LOG(ERR, "Unable to create Mkey");
			goto error;
		}
		entry->addr = (void *)(reg->host_user_addr);
		entry->length = reg->size;
		entry->is_indirect = 0;
		if (i > 0) {
			uint64_t empty_region = reg->guest_phys_addr -
					(mem->regions[i - 1].guest_phys_addr +
					 mem->regions[i - 1].size);
			if (empty_region > 0) {
				uint64_t start_addr =
					mem->regions[i - 1].guest_phys_addr +
					mem->regions[i - 1].size;
				for (uint64_t k = 0;
				     k < empty_region; k += klm_size) {
					klm_array[klm_index].mkey =
						priv->caps.dump_mkey;
					klm_array[klm_index].address =
						start_addr + k;
					klm_index++;
				}
			}
		}
		for (uint64_t k = 0; k < reg->size; k += klm_size) {
			klm_array[klm_index].byte_count = 0;
			klm_array[klm_index].mkey = entry->mkey_ix;
			klm_array[klm_index].address = reg->guest_phys_addr + k;
			klm_index++;
		}
		list_elem->vdpa_query_mr = entry;
		SLIST_INSERT_HEAD(&priv->mr_list, list_elem, next);
	}
	mkey_attr.addr = (uintptr_t)(mem->regions[0].guest_phys_addr);
	mkey_attr.size = mem_size;
	mkey_attr.pd = priv->pdn;
	mkey_attr.pas_id = 0;
	mkey_attr.log_entity_size = rte_log2_u32(klm_size);
	list_elem =
		rte_malloc(__func__, sizeof(*list_elem), RTE_CACHE_LINE_SIZE);
	entry = rte_malloc(__func__, sizeof(*entry), 0);
	if (!entry || !list_elem) {
		DRV_LOG(ERR, "Unable to allocate memory");
		goto error;
	}
	if (mlx5_create_indirect_mkey(priv->mctx, &mkey_attr,
				      klm_array, klm_index, priv->uid,
				      &entry->mkey_ix)) {
		DRV_LOG(ERR, "Unable to create indirect Mkey");
		goto error;
	}
	entry->is_indirect = 1;
	list_elem->vdpa_query_mr = entry;
	SLIST_INSERT_HEAD(&priv->mr_list, list_elem, next);
	priv->gpa_mkey_index = entry->mkey_ix;
	return 0;
error:
	if (list_elem)
		free(list_elem);
	if (entry)
		free(entry);
	return -1;
}

static int
mlx5_vdpa_create_tis(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(create_tis_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(create_tis_out)] = {0};
	int err;

	MLX5_SET(create_tis_in, in, opcode, MLX5_CMD_OP_CREATE_TIS);
	MLX5_SET(create_tis_in, in, uid, priv->uid);
	err = mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out));
	if (err || MLX5_GET(create_tis_out, out, status)) {
		DRV_LOG(ERR, "Can't create TIS");
		return -1;
	}
	priv->tisn = MLX5_GET(create_tis_out, out, tisn);
	DRV_LOG(DEBUG, "Success creating TIS 0x%x", priv->tisn);
	return 0;
}

static int
mlx5_vdpa_dev_config(int vid)
{
	int did;
	struct vdpa_priv_list *list_elem;
	struct vdpa_priv *priv;

	did = rte_vhost_get_vdpa_device_id(vid);
	list_elem = find_priv_resource_by_did(did);
	if (list_elem == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}
	priv = list_elem->priv;
	priv->vid = vid;
	if (create_pd(priv)) {
		DRV_LOG(ERR, "Error allocating PD");
		return -1;
	}
	if (mlx5_vdpa_create_tis(priv)) {
		DRV_LOG(ERR, "Error creating TIS");
		return -1;
	}
	if (mlx5_vdpa_dma_map(priv)) {
		DRV_LOG(ERR, "Error DMA mapping VM memory");
		return -1;
	}
	if (mlx5_vdpa_setup_virtqs(priv)) {
		DRV_LOG(ERR, "Error setting up Virtqueues");
		return -1;
	}
	mlx5_vdpa_setup_notify_relay(priv);
	rte_atomic32_set(&priv->dev_attached, 1);
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
	*features = list_elem->priv->caps.virtio_protocol_features;
	return 0;
}

static int
mlx5_vdpa_query_virtio_caps(struct vdpa_priv *priv)
{
	uint32_t in[MLX5_ST_SZ_DW(query_hca_cap_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(query_hca_cap_out)] = {0};
	uint32_t in_special[MLX5_ST_SZ_DW(query_special_contexts_in)] = {0};
	uint32_t out_special[MLX5_ST_SZ_DW(query_special_contexts_out)] = {0};
	uint8_t dump_mkey_reported = 0;
	void *cap = NULL;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, uid, priv->uid);
	MLX5_SET(query_hca_cap_in, in, op_mod,
			(MLX5_HCA_CAP_GENERAL << 1) |
			(MLX5_HCA_CAP_OPMOD_GET_CUR & 0x1));

	if (mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out, sizeof(out))) {
		DRV_LOG(DEBUG, "Failed to Query Current HCA CAP section");
		return -1;
	}
	cap = MLX5_ADDR_OF(query_hca_cap_out, out, capability);
	dump_mkey_reported = MLX5_GET(cmd_hca_cap, cap, dump_fill_mkey);
	if (!dump_mkey_reported) {
		DRV_LOG(DEBUG, "dump_fill_mkey is not supported");
		return -1;
	}
	/* Query the actual dump key. */
	MLX5_SET(query_special_contexts_in, in_special, opcode,
		 MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS);
	MLX5_SET(query_special_contexts_in, in, uid, priv->uid);
	if (mlx5_mdev_cmd_exec(priv->mctx, in_special,
			       sizeof(in_special), out_special,
			       sizeof(out_special))) {
		DRV_LOG(DEBUG, "Failed to Query Special Contexts");
		return -1;
	}
	priv->caps.dump_mkey = MLX5_GET(query_special_contexts_out,
					out_special,
					dump_fill_mkey);
	/*
	 * TODO (idos): Once we have FW support, exit if not supported
	 */
	if (MLX5_GET64(cmd_hca_cap, cap, general_obj_types) &
			MLX5_GENERAL_OBJ_TYPES_CAP_VIRTQ) {
		DRV_LOG(DEBUG, "Virtio acceleration supported by the device!");
		MLX5_SET(query_hca_cap_in, in, op_mod,
			 (MLX5_HCA_CAP_DEVICE_EMULATION << 1) |
			 (MLX5_HCA_CAP_OPMOD_GET_CUR & 0x1));
		if (mlx5_mdev_cmd_exec(priv->mctx, in, sizeof(in), out,
				       sizeof(out))) {
			DRV_LOG(DEBUG, "Failed to Query Emulation CAP section");
			return -1;
		}
		priv->caps.max_num_virtqs = MLX5_GET(virtio_net_cap,
						     cap,
						     max_num_virtio_queues);
	} else {
		DRV_LOG(DEBUG, "Virtio acceleration not supported by the device");
		priv->caps.max_num_virtqs = MLX5_VDPA_SW_MAX_VIRTQS_SUPPORTED;
	}
	priv->caps.virtio_net_features = MLX5_VDPA_FEATURES;
	priv->caps.virtio_protocol_features = MLX5_VDPA_PROTOCOL_FEATURES;
	DRV_LOG(DEBUG, "Virtio Caps:");
	DRV_LOG(DEBUG, "	dump_mkey=0x%x ", priv->caps.dump_mkey);
	DRV_LOG(DEBUG, "	max_num_virtqs=0x%x ",
			priv->caps.max_num_virtqs);
	DRV_LOG(DEBUG, "	features_bits=0x%" PRIx64,
			priv->caps.virtio_net_features);
	return 0;
}

static int mlx5_vdpa_vfio_setup(struct vdpa_priv *priv)
{
	struct rte_pci_device *dev = priv->pdev;
	char devname[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;

	priv->vfio_dev_fd = -1;
	priv->vfio_group_fd = -1;
	priv->vfio_container_fd = -1;
	rte_pci_device_name(&dev->addr, devname, RTE_DEV_NAME_MAX_LEN);
	rte_vfio_get_group_num(rte_pci_get_sysfs_path(), devname,
			       &iommu_group_num);
	priv->vfio_container_fd = rte_vfio_container_create();
	if (priv->vfio_container_fd < 0)
		return -1;
	priv->vfio_group_fd = rte_vfio_container_group_bind(
			priv->vfio_container_fd, iommu_group_num);
	if (priv->vfio_group_fd < 0)
		goto err;
	if (rte_pci_map_device(dev))
		goto err;
	priv->vfio_dev_fd = dev->intr_handle.vfio_dev_fd;
	return 0;
err:
	rte_vfio_container_destroy(priv->vfio_container_fd);
	return -1;
}

static int mlx5_vdpa_init_device(struct vdpa_priv *priv)
{
	struct rte_pci_device *pdev = priv->pdev;
	const char *drv_ver = "linux,mlx5_vdpa_vfio,1.0.000001";

	priv->base_addr = (void*)pdev->mem_resource[0].addr;
	priv->mctx = mdev_open_device((void*)priv, priv->base_addr,
				      drv_ver, mlx5_vdpa_vfio_dma);
	if (!priv->mctx) {
		DRV_LOG(ERR, "failed to start up device via mdev");
		return -1;
	}
	if (create_uctx(priv)) {
		DRV_LOG(ERR, "failed to crete UCTX");
		return -1;

	}
	return 0;
}

static struct rte_vdpa_dev_ops mlx5_vdpa_ops = {
	.get_queue_num = mlx5_vdpa_get_queue_num,
	.get_features = mlx5_vdpa_get_vdpa_features,
	.get_protocol_features = mlx5_vdpa_get_protocol_features,
	.dev_conf = mlx5_vdpa_dev_config,
	.dev_close = NULL,
	.set_vring_state = NULL,
	.set_features = NULL,
	.migration_done = NULL,
	.get_vfio_group_fd = NULL,
	.get_vfio_device_fd = NULL,
	.get_notify_area = NULL,
};

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
static int
mlx5_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev)
{
	struct vdpa_priv *priv = NULL;
	struct vdpa_priv_list *priv_list_elem = NULL;

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
	if (mlx5_vdpa_vfio_setup(priv)) {
		DRV_LOG(DEBUG, "Unable to init VFIO setup");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	if (mlx5_vdpa_init_device(priv)) {
		DRV_LOG(DEBUG, "Unable to init vDPA HCA");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	if (mlx5_vdpa_query_virtio_caps(priv)) {
		DRV_LOG(DEBUG, "Unable to query Virtio caps");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	priv_list_elem->priv = priv;
	priv->id = rte_vdpa_register_device(&priv->dev_addr,
					     &mlx5_vdpa_ops);
	if (priv->id < 0) {
		DRV_LOG(DEBUG, "Unable to register vDPA device");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}
	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&priv_list, priv_list_elem, next);
	pthread_mutex_unlock(&priv_list_lock);
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
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BFVF)
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

RTE_PMD_REGISTER_PCI(net_mlx5_vdpa, mlx5_vdpa_driver);
RTE_PMD_REGISTER_PCI_TABLE(net_mlx5_vdpa, mlx5_vdpa_pci_id_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mlx5_vdpa, "* vfio-pci");

/**
 * Driver initialization routine.
 */
RTE_INIT(rte_mlx5_vdpa_init)
{
	/* Initialize driver log type. */
	mlx5_vdpa_logtype = rte_log_register("pmd.net.mlx5_vdpa");
	if (mlx5_vdpa_logtype >= 0)
		rte_log_set_level(mlx5_vdpa_logtype, RTE_LOG_NOTICE);
}
