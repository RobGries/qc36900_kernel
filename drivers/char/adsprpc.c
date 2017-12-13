/*
 * Copyright (c) 2012-2014,2016 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/soc/qcom/smd.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/dma-mapping.h>
#include <linux/kref.h>
#include <linux/sort.h>
#include "adsprpc_compat.h"
#include "adsprpc_shared.h"

#define RPC_TIMEOUT	(5 * HZ)
#define RPC_HASH_BITS	5
#define RPC_HASH_SZ	(1 << RPC_HASH_BITS)
#define BALIGN		32

#define LOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				down_read(&current->mm->mmap_sem);\
		} while (0)

#define UNLOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				up_read(&current->mm->mmap_sem);\
		} while (0)


#define IS_CACHE_ALIGNED(x) (((x) & ((L1_CACHE_BYTES)-1)) == 0)

static inline uintptr_t buf_page_start(void *buf)
{
	uintptr_t start = (uintptr_t) buf & PAGE_MASK;

	return start;
}

static inline uintptr_t buf_page_offset(void *buf)
{
	uintptr_t offset = (uintptr_t) buf & (PAGE_SIZE - 1);

	return offset;
}

static inline int buf_num_pages(void *buf, ssize_t len)
{
	uintptr_t start = buf_page_start(buf) >> PAGE_SHIFT;
	uintptr_t end = (((uintptr_t) buf + len - 1) & PAGE_MASK) >> PAGE_SHIFT;
	int nPages = end - start + 1;

	return nPages;
}

static inline uint32_t buf_page_size(uint32_t size)
{
	uint32_t sz = (size + (PAGE_SIZE - 1)) & PAGE_MASK;

	return sz > PAGE_SIZE ? sz : PAGE_SIZE;
}

struct fastrpc_buf {
	void *virt;
	dma_addr_t phys;
	ssize_t size;
	struct dma_attrs attrs;
	int used;
};

struct overlap {
	uintptr_t start;
	uintptr_t end;
	int raix;
	uintptr_t mstart;
	uintptr_t mend;
	uintptr_t offset;
};

struct smq_invoke_ctx {
	struct hlist_node hn;
	struct completion work;
	int retval;
	int pid;
	int tgid;
	remote_arg_t *pra;
	remote_arg_t *rpra;
	struct fastrpc_buf obuf;
	struct fastrpc_buf *abufs;
	struct fastrpc_device *dev;
	struct fastrpc_apps *apps;
	struct file_data *fdata;
	int nbufs;
	uint32_t sc;
	struct overlap *overs;
	struct overlap **overps;
	struct page **pg;
	struct page ***ppg;
};

struct smq_context_list {
	struct hlist_head pending;
	struct hlist_head interrupted;
	rwlock_t lock;
};

struct fastrpc_apps {
	struct smq_context_list clst;
	struct cdev cdev;
	struct class *class;
	dev_t dev_no;
	int compat;
	spinlock_t hlock;
	struct hlist_head htbl[RPC_HASH_SZ];
	struct device *dev;
	struct qcom_smd_device *qsdev;
};

struct fastrpc_mmap {
	struct hlist_node hn;
	void *virt;
	dma_addr_t phys;
	uintptr_t vaddrin;
	uintptr_t vaddrout;
	ssize_t size;
	int refs;
	struct page **pg;
};

struct file_data {
	spinlock_t hlock;
	struct hlist_head hlst;
	uint32_t mode;
	int cid;
	int tgid;
};

struct fastrpc_device {
	uint32_t tgid;
	struct hlist_node hn;
	struct fastrpc_buf buf;
};

static struct fastrpc_apps gfa;

static void free_mem(struct fastrpc_buf *buf)
{
	struct fastrpc_apps *me = &gfa;

	if (!IS_ERR_OR_NULL(buf->virt)) {
		dma_free_attrs(&me->qsdev->dev, buf->size, buf->virt,
				buf->phys, &buf->attrs);
		buf->virt = 0;
	}
}

static int alloc_mem(struct fastrpc_buf *buf)
{
	struct fastrpc_apps *me = &gfa;
	int err = 0;
	DEFINE_DMA_ATTRS(attrs);

	VERIFY(err, me->qsdev);
	if (err)
		goto bail;
	dma_set_mask(&me->qsdev->dev, DMA_BIT_MASK(32));
	dma_set_attr(DMA_ATTR_FORCE_CONTIGUOUS, &attrs);

	buf->virt = dma_alloc_attrs(&me->qsdev->dev,
				buf->size, &buf->phys, GFP_KERNEL, &attrs);
	VERIFY(err, !IS_ERR_OR_NULL(buf->virt));
	if (err)
		goto bail;
	buf->attrs = attrs;
bail:
	return err;
}

static int context_restore_interrupted(struct fastrpc_apps *me,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				struct file_data *fdata,
				struct smq_invoke_ctx **po)
{
	int err = 0;
	struct smq_invoke_ctx *ctx = 0, *ictx = 0;
	struct hlist_node *n;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	unsigned long flags;

	write_lock_irqsave(&me->clst.lock, flags);
	hlist_for_each_entry_safe(ictx, n, &me->clst.interrupted, hn) {
		if (ictx->pid == current->pid) {
			if (invoke->sc != ictx->sc || ictx->fdata != fdata)
				err = -1;
			else {
				ctx = ictx;
				hlist_del(&ctx->hn);
				hlist_add_head(&ctx->hn, &me->clst.pending);
			}
			break;
		}
	}
	write_unlock_irqrestore(&me->clst.lock, flags);
	if (ctx)
		*po = ctx;
	return err;
}

#define CMP(aa, bb) ((aa) == (bb) ? 0 : (aa) < (bb) ? -1 : 1)
static int overlap_ptr_cmp(const void *a, const void *b)
{
	struct overlap *pa = *((struct overlap **)a);
	struct overlap *pb = *((struct overlap **)b);
	/* sort with lowest starting buffer first */
	int st = CMP(pa->start, pb->start);
	/* sort with highest ending buffer first */
	int ed = CMP(pb->end, pa->end);
	return st == 0 ? ed : st;
}

static int context_build_overlap(struct smq_invoke_ctx *ctx)
{
	int err = 0, i;
	remote_arg_t *pra = ctx->pra;
	int inbufs = REMOTE_SCALARS_INBUFS(ctx->sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(ctx->sc);
	int nbufs = inbufs + outbufs;
	struct overlap max;

	ctx->overs = kzalloc(sizeof(*ctx->overs) * (nbufs), GFP_KERNEL);
	VERIFY(err, !IS_ERR_OR_NULL(ctx->overs));
	if (err)
		goto bail;
	ctx->overps = kzalloc(sizeof(*ctx->overps) * (nbufs), GFP_KERNEL);
	VERIFY(err, !IS_ERR_OR_NULL(ctx->overps));
	if (err)
		goto bail;
	for (i = 0; i < nbufs; ++i) {
		ctx->overs[i].start = (uintptr_t)pra[i].buf.pv;
		ctx->overs[i].end = ctx->overs[i].start + pra[i].buf.len;
		ctx->overs[i].raix = i;
		ctx->overps[i] = &ctx->overs[i];
	}
	sort(ctx->overps, nbufs, sizeof(*ctx->overps), overlap_ptr_cmp, 0);
	max.start = 0;
	max.end = 0;
	for (i = 0; i < nbufs; ++i) {
		if (ctx->overps[i]->start < max.end) {
			ctx->overps[i]->mstart = max.end;
			ctx->overps[i]->mend = ctx->overps[i]->end;
			ctx->overps[i]->offset = max.end -
				ctx->overps[i]->start;
			if (ctx->overps[i]->end > max.end) {
				max.end = ctx->overps[i]->end;
			} else {
				ctx->overps[i]->mend = 0;
				ctx->overps[i]->mstart = 0;
			}
		} else  {
			ctx->overps[i]->mend = ctx->overps[i]->end;
			ctx->overps[i]->mstart = ctx->overps[i]->start;
			ctx->overps[i]->offset = 0;
			max = *ctx->overps[i];
		}
	}
bail:
	return err;
}

static void add_dev(struct fastrpc_apps *me, struct fastrpc_device *dev)
{
	struct hlist_head *head;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_add_head(&dev->hn, head);
	spin_unlock(&me->hlock);
}

static void context_free(struct smq_invoke_ctx *ctx, int remove)
{
	struct smq_context_list *clst = &ctx->apps->clst;
	struct fastrpc_apps *apps = ctx->apps;
	struct fastrpc_buf *b;
	int i, j, inbufs, outbufs, num, offset = 0;
	unsigned long flags;

	inbufs = REMOTE_SCALARS_INBUFS(ctx->sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(ctx->sc);
	for (i = 0; i < inbufs + outbufs; i++) {
		if (!ctx->pg[offset])
			continue;
		num = buf_num_pages(ctx->pra[i].buf.pv, ctx->pra[i].buf.len);
		for (j = 0; j < num; j++) {
			if (i >= inbufs)
				SetPageDirty(ctx->pg[offset + j]);
			page_cache_release(ctx->pg[offset + j]);
		}
		offset += num;
	}
	for (i = 0, b = ctx->abufs; i < ctx->nbufs; ++i, ++b)
		free_mem(b);

	kfree(ctx->abufs);
	if (ctx->dev) {
		add_dev(apps, ctx->dev);
		if (ctx->obuf.virt != ctx->dev->buf.virt)
			free_mem(&ctx->obuf);
	}
	if (remove) {
		write_lock_irqsave(&clst->lock, flags);
		hlist_del(&ctx->hn);
		write_unlock_irqrestore(&clst->lock, flags);
	}
	kfree(ctx->overps);
	kfree(ctx->overs);
	kfree(ctx->pg);
	kfree(ctx);
}

static int context_alloc(struct fastrpc_apps *me, uint32_t kernel,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				struct file_data *fdata,
				struct smq_invoke_ctx **po)
{
	int i, err = 0, bufs, size = 0;
	struct smq_invoke_ctx *ctx = 0;
	struct smq_context_list *clst = &me->clst;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	unsigned long flags;

	bufs = REMOTE_SCALARS_INBUFS(invoke->sc) +
			REMOTE_SCALARS_OUTBUFS(invoke->sc);
	if (bufs) {
		size = bufs * sizeof(*ctx->pg);
		size += bufs * sizeof(*ctx->pra);
	}

	VERIFY(err, 0 != (ctx = kzalloc(sizeof(*ctx) + size, GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&ctx->hn);
	ctx->apps = me;
	ctx->fdata = fdata;
	ctx->ppg = (struct page ***)(&ctx[1]);
	ctx->pra = (remote_arg_t *)(&ctx->ppg[bufs]);
	if (!kernel) {
		VERIFY(err, 0 == copy_from_user(ctx->pra, invoke->pra,
					bufs * sizeof(*ctx->pra)));
		if (err)
			goto bail;
	} else {
		memmove(ctx->pra, invoke->pra, bufs * sizeof(*ctx->pra));
	}

	ctx->sc = invoke->sc;
	size = 0;
	for (i = 0; i < bufs; i++) {
		if (!ctx->pra[i].buf.len)
			continue;
		size += buf_num_pages(ctx->pra[i].buf.pv, ctx->pra[i].buf.len);
	}
	if (size) {
		VERIFY(err, 0 != (ctx->pg = kcalloc(size, sizeof(*ctx->pg),
							GFP_KERNEL)));
		if (err)
			goto bail;
		size = 0;
		for (i = 0; i < bufs; i++) {
			ctx->ppg[i] = ctx->pg + size;
			size += buf_num_pages(ctx->pra[i].buf.pv,
						ctx->pra[i].buf.len);
		}
	}
	if (bufs) {
		VERIFY(err, 0 == context_build_overlap(ctx));
		if (err)
			goto bail;
	}
	ctx->retval = -1;
	ctx->pid = current->pid;
	ctx->tgid = current->tgid;
	init_completion(&ctx->work);
	write_lock_irqsave(&clst->lock, flags);
	hlist_add_head(&ctx->hn, &clst->pending);
	write_unlock_irqrestore(&clst->lock, flags);

	*po = ctx;
bail:
	if (ctx && err)
		context_free(ctx, 1);
	return err;
}

static void context_save_interrupted(struct smq_invoke_ctx *ctx)
{
	struct smq_context_list *clst = &ctx->apps->clst;
	unsigned long flags;

	write_lock_irqsave(&clst->lock, flags);
	hlist_del(&ctx->hn);
	hlist_add_head(&ctx->hn, &clst->interrupted);
	write_unlock_irqrestore(&clst->lock, flags);
}

static void context_notify_user(uint32_t pid, uint32_t tid, int retval)
{
	struct smq_context_list *me = &gfa.clst;
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *n;

	read_lock(&me->lock);
	hlist_for_each_entry_safe(ictx, n, &me->pending, hn) {
		if (ictx->tgid == tid && ictx->pid == pid) {
			ictx->retval = retval;
			complete(&ictx->work);
		}
	}
	read_unlock(&me->lock);
}

static void context_notify_all_users(struct smq_context_list *me)
{
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *n;

	read_lock(&me->lock);
	hlist_for_each_entry_safe(ictx, n, &me->pending, hn) {
		complete(&ictx->work);
	}
	hlist_for_each_entry_safe(ictx, n, &me->interrupted, hn) {
		complete(&ictx->work);
	}
	read_unlock(&me->lock);

}

static void context_list_ctor(struct smq_context_list *me)
{
	INIT_HLIST_HEAD(&me->interrupted);
	INIT_HLIST_HEAD(&me->pending);
	rwlock_init(&me->lock);
}

static void context_list_dtor(struct fastrpc_apps *me,
				struct smq_context_list *clst)
{
	struct smq_invoke_ctx *ictx = 0, *ctxfree;
	struct hlist_node *n;
	unsigned long flags;

	do {
		ctxfree = 0;
		write_lock_irqsave(&clst->lock, flags);
		hlist_for_each_entry_safe(ictx, n, &clst->interrupted, hn) {
			hlist_del(&ictx->hn);
			ctxfree = ictx;
			break;
		}
		write_unlock_irqrestore(&clst->lock, flags);
		if (ctxfree)
			context_free(ctxfree, 0);
	} while (ctxfree);
	do {
		ctxfree = 0;
		write_lock_irqsave(&clst->lock, flags);
		hlist_for_each_entry_safe(ictx, n, &clst->pending, hn) {
			hlist_del(&ictx->hn);
			ctxfree = ictx;
			break;
		}
		write_unlock_irqrestore(&clst->lock, flags);
		if (ctxfree)
			context_free(ctxfree, 0);
	} while (ctxfree);
}

static int buf_get_user_pages(struct smq_invoke_ctx *ctx, int id, int offset,
				int access, struct smq_phy_page *pages)
{
	uintptr_t start = buf_page_start(ctx->pra[id].buf.pv);
	ssize_t len = ctx->pra[id].buf.len;
	unsigned long pfnstart, pfnlast, pfn = 0;
	struct hlist_node *n;
	struct fastrpc_mmap *map, *mapmatch = 0;
	int i, nr_pages, num = 0, err = 0;

	nr_pages = buf_num_pages(ctx->pra[id].buf.pv, ctx->pra[id].buf.len);
	if (nr_pages <= 1) {
		spin_lock(&ctx->fdata->hlock);
		hlist_for_each_entry_safe(map, n, &ctx->fdata->hlst, hn) {
			if (start >= map->vaddrin &&
				start + len <= map->vaddrin + map->size) {
				mapmatch = map;
				break;
			}
		}
		spin_unlock(&ctx->fdata->hlock);
		if (!mapmatch)
			return 0;
	}
	VERIFY(err, nr_pages == get_user_pages_unlocked(current, current->mm,
			start, nr_pages, access, 0, &ctx->pg[offset]));
	if (err)
		return -1;
	pfnstart = pfnlast = page_to_pfn(ctx->pg[offset]);
	for (i = 1; i <= nr_pages; i++) {
		if (i < nr_pages) {
			pfn = __page_to_pfn(ctx->pg[offset + i]);
			if (pfn == pfnlast + 1) {
				pfnlast = pfn;
				continue;
			}
		}
		pages[num].addr = __pfn_to_phys(pfnstart);
		pages[num].size = (pfnlast - pfnstart + 1) << PAGE_SHIFT;
		VERIFY(err, pages[num].addr < U32_MAX);
		if (err)
			return 0;
		num++;
		pfnstart = pfnlast = pfn;
	}
	return num;
}

static int get_page_list(uint32_t kernel, struct smq_invoke_ctx *ctx)
{
	struct smq_phy_page *pgstart, *pages;
	struct smq_invoke_buf *list;
	struct fastrpc_buf *ibuf = &ctx->dev->buf;
	struct fastrpc_buf *obuf = &ctx->obuf;
	remote_arg_t *pra = ctx->pra;
	ssize_t rlen;
	uint32_t sc = ctx->sc;
	int i, err = 0, num;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);

	*obuf = *ibuf;
 retry:
	list = smq_invoke_buf_start((remote_arg_t *)obuf->virt, sc);
	pgstart = smq_phy_page_start(sc, list);
	pages = pgstart + 1;
	rlen = obuf->size - ((uintptr_t)pages - (uintptr_t)obuf->virt);
	num = 0;
	for (i = 0; i < inbufs + outbufs; ++i) {
		if (!pra[i].buf.len)
			continue;
		num += buf_num_pages(pra[i].buf.pv, pra[i].buf.len);
	}
	if (rlen < num * sizeof(*pages)) {
		rlen = ((uintptr_t)pages - (uintptr_t)obuf->virt) +
					num * sizeof(*pages);
		obuf->size = buf_page_size(rlen);
		VERIFY(err, 0 == alloc_mem(obuf));
		if (err)
			goto bail;
		goto retry;
	}
	pgstart->addr = obuf->phys;
	pgstart->size = obuf->size;
	num = 0;
	for (i = 0; i < inbufs + outbufs; ++i) {
		list[i].num = 0;
		list[i].pgidx = 0;
		VERIFY(err, pra[i].buf.len >= 0);
		if (err)
			goto bail;
		if (!pra[i].buf.len)
			continue;
		if (!kernel)
			list[i].num = buf_get_user_pages(ctx, i, num,
						i >= inbufs, pages);
		VERIFY(err, list[i].num >= 0);
		if (err)
			goto bail;
		num += buf_num_pages(pra[i].buf.pv, pra[i].buf.len);
		if (list[i].num) {
			list[i].pgidx = pages - pgstart;
			pages = pages + list[i].num;
		} else {
			list[i].pgidx = pages - pgstart;
			pages = pages + 1;
		}
	}
	obuf->used = obuf->size;
 bail:
	if (err && (obuf->virt != ibuf->virt))
		free_mem(obuf);
	return err;
}

static int get_args(uint32_t kernel, struct smq_invoke_ctx *ctx,
			remote_arg_t *upra)
{
	struct smq_invoke_buf *list;
	struct fastrpc_buf *pbuf = &ctx->obuf, *obufs = 0;
	struct smq_phy_page *pages;
	void *args;
	remote_arg_t *pra = ctx->pra;
	remote_arg_t *rpra = ctx->rpra;
	ssize_t rlen, used, size;
	uint32_t sc = ctx->sc;
	int i, inh, bufs = 0, err = 0, oix, copylen = 0;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);

	list = smq_invoke_buf_start(rpra, sc);
	pages = smq_phy_page_start(sc, list);
	used = ALIGN(pbuf->used, BALIGN);
	args = (void *)((char *)pbuf->virt + used);
	rlen = pbuf->size - used;

	/* map buffers */
	for (i = 0; i < inbufs + outbufs; ++i) {
		rpra[i].buf.len = pra[i].buf.len;
		if (!pra[i].buf.len)
			continue;
		if (list[i].num) {
			rpra[i].buf.pv = pra[i].buf.pv;
			continue;
		}
	}

	/* calculate len required for copying */
	for (oix = 0; oix < inbufs + outbufs; ++oix) {
		int i = ctx->overps[oix]->raix;

		if (!pra[i].buf.len)
			continue;
		if (list[i].num)
			continue;
		if (ctx->overps[oix]->offset == 0)
			copylen = ALIGN(copylen, BALIGN);
		copylen += ctx->overps[oix]->mend - ctx->overps[oix]->mstart;
	}

	/* allocate new buffer */
	if (copylen > rlen) {
		struct fastrpc_buf *b;

		pbuf->used = pbuf->size - rlen;
		VERIFY(err, 0 != (b = krealloc(obufs,
			 (bufs + 1) * sizeof(*obufs), GFP_KERNEL)));
		if (err)
			goto bail;
		obufs = b;
		pbuf = obufs + bufs;
		pbuf->size = buf_num_pages(0, copylen) * PAGE_SIZE;
		VERIFY(err, 0 == alloc_mem(pbuf));
		if (err)
			goto bail;
		bufs++;
		args = pbuf->virt;
		rlen = pbuf->size;

	}

	/* copy buffers */
	for (oix = 0; oix < inbufs + outbufs; ++oix) {
		int i = ctx->overps[oix]->raix;
		int mlen = ctx->overps[oix]->mend - ctx->overps[oix]->mstart;

		if (!pra[i].buf.len)
			continue;
		if (list[i].num)
			continue;

		if (ctx->overps[oix]->offset == 0) {
			rlen -= ALIGN((uintptr_t)args, BALIGN) -
				(uintptr_t)args;
			args = (void *)ALIGN((uintptr_t)args, BALIGN);
		}
		VERIFY(err, rlen >= mlen);
		if (err)
			goto bail;
		list[i].num = 1;
		pages[list[i].pgidx].addr =
			buf_page_start((void *)((uintptr_t)pbuf->phys -
						ctx->overps[oix]->offset +
						 (pbuf->size - rlen)));
		pages[list[i].pgidx].size =
			buf_page_size(pra[i].buf.len);
		if (i < inbufs && mlen) {
			if (!kernel) {
				VERIFY(err, 0 == copy_from_user(args,
					(void *)ctx->overps[oix]->mstart,
					mlen));
				if (err)
					goto bail;
			} else {
				memmove(args, (void *)ctx->overps[oix]->mstart,
					mlen);
			}
		}
		rpra[i].buf.pv = args - ctx->overps[oix]->offset;
		args = (void *)((uintptr_t)args + mlen);
		rlen -= mlen;
	}

	for (i = 0; i < inbufs; ++i) {
		if (rpra[i].buf.len)
			dmac_flush_range(rpra[i].buf.pv,
				  (char *)rpra[i].buf.pv + rpra[i].buf.len);
	}
	pbuf->used = pbuf->size - rlen;
	size = sizeof(*rpra) * REMOTE_SCALARS_INHANDLES(sc);
	if (size) {
		inh = inbufs + outbufs;
		if (!kernel) {
			VERIFY(err, 0 == copy_from_user(&rpra[inh], &upra[inh],
							size));
			if (err)
				goto bail;
		} else {
			memmove(&rpra[inh], &upra[inh], size);
		}
	}
	dmac_flush_range(rpra, (char *)rpra + used);
 bail:
	ctx->abufs = obufs;
	ctx->nbufs = bufs;
	return err;
}

static int put_args(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			remote_arg_t *rpra, remote_arg_t *upra)
{
	int i, inbufs, outbufs, outh, size;
	int err = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (rpra[i].buf.pv != pra[i].buf.pv) {
			if (!kernel) {
				VERIFY(err, 0 == copy_to_user(pra[i].buf.pv,
					rpra[i].buf.pv, rpra[i].buf.len));
				if (err)
					goto bail;
			} else {
				memmove(pra[i].buf.pv, rpra[i].buf.pv,
							rpra[i].buf.len);
			}
		}
	}
	size = sizeof(*rpra) * REMOTE_SCALARS_OUTHANDLES(sc);
	if (size) {
		outh = inbufs + outbufs + REMOTE_SCALARS_INHANDLES(sc);
		if (!kernel) {
			VERIFY(err, 0 == copy_to_user(&upra[outh], &rpra[outh],
						size));
			if (err)
				goto bail;
		} else {
			memmove(&upra[outh], &rpra[outh], size);
		}
	}
 bail:
	return err;
}

static void inv_args_pre(uint32_t sc, remote_arg_t *rpra)
{
	int i, inbufs, outbufs;
	uintptr_t end;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (!rpra[i].buf.len)
			continue;
		if (buf_page_start(rpra) == buf_page_start(rpra[i].buf.pv))
			continue;
		if (!IS_CACHE_ALIGNED((uintptr_t)rpra[i].buf.pv))
			dmac_flush_range(rpra[i].buf.pv,
				(char *)rpra[i].buf.pv + 1);
		end = (uintptr_t)rpra[i].buf.pv + rpra[i].buf.len;
		if (!IS_CACHE_ALIGNED(end))
			dmac_flush_range((char *)end,
				(char *)end + 1);
	}
}

static void inv_args(uint32_t sc, remote_arg_t *rpra, int used)
{
	int i, inbufs, outbufs;
	int inv = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (buf_page_start(rpra) == buf_page_start(rpra[i].buf.pv))
			inv = 1;
		else if (rpra[i].buf.len)
			dmac_inv_range(rpra[i].buf.pv,
				(char *)rpra[i].buf.pv + rpra[i].buf.len);
	}

	if (inv || REMOTE_SCALARS_OUTHANDLES(sc))
		dmac_inv_range(rpra, (char *)rpra + used);
}

static int fastrpc_invoke_send(struct fastrpc_apps *me,
				 uint32_t kernel, uint32_t handle,
				 uint32_t sc, struct smq_invoke_ctx *ctx,
				 struct fastrpc_buf *buf)
{
	struct smq_msg msg;
	int err = 0;

	msg.pid = current->tgid;
	msg.tid = current->pid;
	if (kernel)
		msg.pid = 0;
	msg.invoke.header.pid = ctx->pid;
	msg.invoke.header.tid = ctx->tgid;
	msg.invoke.header.handle = handle;
	msg.invoke.header.sc = sc;
	msg.invoke.page.addr = buf->phys;
	msg.invoke.page.size = buf_page_size(buf->used);
	err = qcom_smd_send(me->qsdev->channel, &msg, sizeof(msg));
	return err;
}

static void fastrpc_deinit(void)
{
	struct fastrpc_apps *me = &gfa;

	device_destroy(me->class, MKDEV(MAJOR(me->dev_no), 0));
	class_destroy(me->class);
	cdev_del(&me->cdev);
	unregister_chrdev_region(me->dev_no, 1);
}

static int fastrpc_init(void)
{
	int i;
	struct fastrpc_apps *me = &gfa;

	spin_lock_init(&me->hlock);
	context_list_ctor(&me->clst);
	for (i = 0; i < RPC_HASH_SZ; ++i)
		INIT_HLIST_HEAD(&me->htbl[i]);
	return 0;
}

static void free_dev(struct fastrpc_device *dev, struct file_data *fdata)
{
	if (dev) {
		free_mem(&dev->buf);
		kfree(dev);
		module_put(THIS_MODULE);
	}
}

static int alloc_dev(struct fastrpc_device **dev, struct file_data *fdata)
{
	int err = 0;
	struct fastrpc_device *fd = 0;

	VERIFY(err, 0 != try_module_get(THIS_MODULE));
	if (err)
		goto bail;
	VERIFY(err, 0 != (fd = kzalloc(sizeof(*fd), GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&fd->hn);

	fd->buf.size = PAGE_SIZE;
	VERIFY(err, 0 == alloc_mem(&fd->buf));
	if (err)
		goto bail;
	fd->tgid = current->tgid;

	*dev = fd;
 bail:
	if (err)
		free_dev(fd, fdata);
	return err;
}

static int get_dev(struct fastrpc_apps *me, struct file_data *fdata,
			struct fastrpc_device **rdev)
{
	struct hlist_head *head;
	struct fastrpc_device *dev = 0, *devfree = 0;
	struct hlist_node *n;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	int err = 0;

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	VERIFY(err, devfree != 0);
	if (err)
		goto bail;
	*rdev = devfree;
 bail:
	if (err) {
		free_dev(devfree, fdata);
		err = alloc_dev(rdev, fdata);
	}
	return err;
}

static int fastrpc_release_current_dsp_process(struct file_data *fdata);

static int fastrpc_internal_invoke(struct fastrpc_apps *me, uint32_t mode,
			uint32_t kernel,
			struct fastrpc_ioctl_invoke_fd *invokefd,
			struct file_data *fdata)
{
	struct smq_invoke_ctx *ctx = 0;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	int interrupted = 0;
	int err = 0;

	if (!kernel) {
		VERIFY(err, 0 == context_restore_interrupted(me, invokefd,
								fdata, &ctx));
		if (err)
			goto bail;
		if (ctx)
			goto wait;
	}

	VERIFY(err, 0 == context_alloc(me, kernel, invokefd, fdata, &ctx));
	if (err)
		goto bail;

	if (REMOTE_SCALARS_LENGTH(ctx->sc)) {
		VERIFY(err, 0 == get_dev(me, fdata, &ctx->dev));
		if (err)
			goto bail;
		VERIFY(err, 0 == get_page_list(kernel, ctx));
		if (err)
			goto bail;
		ctx->rpra = (remote_arg_t *)ctx->obuf.virt;
		VERIFY(err, 0 == get_args(kernel, ctx, invoke->pra));
		if (err)
			goto bail;
	}

	inv_args_pre(ctx->sc, ctx->rpra);
	if (mode == FASTRPC_MODE_SERIAL)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
	VERIFY(err, 0 == fastrpc_invoke_send(me, kernel, invoke->handle,
						ctx->sc, ctx, &ctx->obuf));
	if (err)
		goto bail;
	if (mode == FASTRPC_MODE_PARALLEL)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
 wait:
	if (kernel)
		wait_for_completion(&ctx->work);
	else {
		interrupted = wait_for_completion_interruptible(&ctx->work);
		VERIFY(err, 0 == (err = interrupted));
		if (err)
			goto bail;
	}
	VERIFY(err, 0 == (err = ctx->retval));
	if (err)
		goto bail;
	VERIFY(err, 0 == put_args(kernel, ctx->sc, ctx->pra, ctx->rpra,
					invoke->pra));
	if (err)
		goto bail;
 bail:
	if (ctx && interrupted == -ERESTARTSYS)
		context_save_interrupted(ctx);
	else if (ctx)
		context_free(ctx, 1);
	return err;
}

static int buf_get_map_pages(void *addr, int nr_pages, int access,
				struct smq_phy_page *pages,
				struct fastrpc_mmap *map)
{
	uintptr_t start = buf_page_start(addr);
	unsigned long pfnstart, pfnlast, pfn = 0;
	int i, num = 0, err = 0;

	VERIFY(err, nr_pages == get_user_pages_unlocked(current, current->mm,
			start, nr_pages, access, 0, map->pg));
	if (err)
		return -1;
	pfnstart = pfnlast = page_to_pfn(map->pg[0]);
	for (i = 1; i <= nr_pages; i++) {
		if (i < nr_pages) {
			pfn = __page_to_pfn(map->pg[i]);
			if (pfn == pfnlast + 1) {
				pfnlast = pfn;
				continue;
			}
		}
		pages[num].addr = __pfn_to_phys(pfnstart);
		pages[num].size = (pfnlast - pfnstart + 1) << PAGE_SHIFT;
		VERIFY(err, pages[num].addr < U32_MAX);
		if (err)
			return -1;
		num++;
		pfnstart = pfnlast = pfn;
	}
	return num;
}

static void free_map(struct fastrpc_mmap *map)
{
	int num, j;

	if (!map)
		return;

	num = buf_num_pages((void *)map->vaddrin, map->size);
	for (j = 0; j < num; j++) {
		SetPageDirty(map->pg[j]);
		page_cache_release(map->pg[j]);
	}
	kfree(map);
}

static int map_buffer(struct fastrpc_apps *me, struct file_data *fdata,
			char *buf, unsigned long len,
			struct fastrpc_mmap **ppmap,
			struct smq_phy_page **ppages, int *pnpages)
{
	struct fastrpc_mmap *map = 0, *mapmatch = 0;
	struct smq_phy_page *pages = 0;
	struct hlist_node *n;
	uintptr_t vaddrout = 0;
	int num;
	int err = 0;

	spin_lock(&fdata->hlock);
	hlist_for_each_entry_safe(map, n, &fdata->hlst, hn) {
		if ((uintptr_t)buf >= map->vaddrin &&
			(uintptr_t)buf + len <= map->vaddrin + map->size) {
			map->refs++;
			mapmatch = map;
			break;
		}
	}
	spin_unlock(&fdata->hlock);
	if (mapmatch) {
		vaddrout = mapmatch->vaddrout;
		return 0;
	}
	num = buf_num_pages(buf, len);
	VERIFY(err, 0 != (map = kzalloc(sizeof(*map) + num * sizeof(*map->pg),
				GFP_KERNEL)));
	if (err)
		goto bail;
	VERIFY(err, 0 != (pages = kcalloc(num, sizeof(*pages), GFP_KERNEL)));
	if (err)
		goto bail;

	map->pg = (struct page **)&map[1];
	VERIFY(err, 0 < (num = buf_get_map_pages(buf, num, 1, pages, map)));
	if (err)
		goto bail;
	map->refs = 1;
	INIT_HLIST_NODE(&map->hn);
	map->vaddrin = (uintptr_t)buf;
	map->vaddrout = vaddrout;
	map->size = len;
	if (ppages)
		*ppages = pages;
	pages = 0;
	if (pnpages)
		*pnpages = num;
	if (ppmap)
		*ppmap = map;
	map = 0;
 bail:
	free_map(map);
	kfree(pages);
	return err;
}

static int fastrpc_init_process(struct file_data *fdata,
				struct fastrpc_ioctl_init *init)
{
	int err = 0;
	struct fastrpc_ioctl_invoke_fd ioctl;
	struct smq_phy_page *pages = 0;
	struct fastrpc_mmap *map = 0;
	struct fastrpc_apps *me = &gfa;

	if (init->flags == FASTRPC_INIT_ATTACH) {
		remote_arg_t ra[1];
		int tgid = current->tgid;

		ra[0].buf.pv = &tgid;
		ra[0].buf.len = sizeof(tgid);
		ioctl.inv.handle = 1;
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(0, 1, 0);
		ioctl.inv.pra = ra;
		ioctl.fds = 0;
		VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
			FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
		if (err)
			goto bail;
	} else {
		err = -ENOTTY;
	}
bail:
	kfree(pages);
	if (err)
		free_map(map);
	return err;
}

static int fastrpc_release_current_dsp_process(struct file_data *fdata)
{
	int err = 0;
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int tgid = 0;

	tgid = fdata->tgid;
	ra[0].buf.pv = &tgid;
	ra[0].buf.len = sizeof(tgid);
	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(1, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	return err;
}

static int fastrpc_mmap_on_dsp(struct fastrpc_apps *me,
					 struct fastrpc_ioctl_mmap *mmap,
					 struct smq_phy_page *pages,
					 struct file_data *fdata, int num)
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[3];
	int err = 0;
	struct {
		int pid;
		uint32_t flags;
		uintptr_t vaddrin;
		int num;
	} inargs;

	struct {
		uintptr_t vaddrout;
	} routargs;
	inargs.pid = current->tgid;
	inargs.vaddrin = (uintptr_t)mmap->vaddrin;
	inargs.flags = mmap->flags;
	inargs.num = me->compat ? num * sizeof(*pages) : num;
	ra[0].buf.pv = &inargs;
	ra[0].buf.len = sizeof(inargs);

	ra[1].buf.pv = pages;
	ra[1].buf.len = num * sizeof(*pages);

	ra[2].buf.pv = &routargs;
	ra[2].buf.len = sizeof(routargs);

	ioctl.inv.handle = 1;
	if (me->compat)
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(4, 2, 1);
	else
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(2, 2, 1);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	mmap->vaddrout = (uintptr_t)routargs.vaddrout;
	if (err)
		goto bail;
bail:
	return err;
}

static int fastrpc_munmap_on_dsp(struct fastrpc_apps *me,
				 struct fastrpc_ioctl_munmap *munmap,
				struct file_data *fdata)
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int err = 0;
	struct {
		int pid;
		uintptr_t vaddrout;
		ssize_t size;
	} inargs;

	inargs.pid = current->tgid;
	inargs.size = munmap->size;
	inargs.vaddrout = munmap->vaddrout;
	ra[0].buf.pv = &inargs;
	ra[0].buf.len = sizeof(inargs);

	ioctl.inv.handle = 1;
	if (me->compat)
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(5, 1, 0);
	else
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(3, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	return err;
}

static int fastrpc_internal_munmap(struct fastrpc_apps *me,
				   struct file_data *fdata,
				   struct fastrpc_ioctl_munmap *munmap)
{
	int err = 0;
	struct fastrpc_mmap *map = 0, *mapfree = 0;
	struct hlist_node *n;

	spin_lock(&fdata->hlock);
	hlist_for_each_entry_safe(map, n, &fdata->hlst, hn) {
		if (map->vaddrout == munmap->vaddrout &&
		    map->size == munmap->size && --map->refs == 0) {
			hlist_del(&map->hn);
			mapfree = map;
			break;
		}
	}
	spin_unlock(&fdata->hlock);
	if (mapfree) {
		VERIFY(err, 0 == (err = fastrpc_munmap_on_dsp(me, munmap,
								fdata)));
		free_map(mapfree);
	}
	return err;
}

static int fastrpc_internal_mmap(struct fastrpc_apps *me,
				 struct file_data *fdata,
				 struct fastrpc_ioctl_mmap *mmap)
{

	struct fastrpc_mmap *map = 0;
	struct smq_phy_page *pages = 0;
	int num = 0;
	int err = 0;

	VERIFY(err, 0 == map_buffer(me, fdata, (char *)mmap->vaddrin,
					mmap->size, &map, &pages, &num));
	if (err)
		goto bail;
	VERIFY(err, 0 == fastrpc_mmap_on_dsp(me, mmap, pages, fdata, num));
	if (err)
		goto bail;
	map->vaddrout = mmap->vaddrout;
	spin_lock(&fdata->hlock);
	hlist_add_head(&map->hn, &fdata->hlst);
	spin_unlock(&fdata->hlock);
 bail:
	if (err && map)
		free_map(map);
	kfree(pages);
	return err;
}

static void cleanup_current_dev(struct file_data *fdata)
{
	struct fastrpc_apps *me = &gfa;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	struct hlist_head *head;
	struct hlist_node *n;
	struct fastrpc_device *dev, *devfree;

 rnext:
	devfree = dev = 0;
	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	if (devfree) {
		free_dev(devfree, fdata);
		goto rnext;
	}
}

static int fastrpc_device_release(struct inode *inode, struct file *file)
{
	struct file_data *fdata = (struct file_data *)file->private_data;
	struct fastrpc_apps *me = &gfa;
	struct smq_context_list *clst = &me->clst;
	struct smq_invoke_ctx *ictx = 0, *ctxfree;
	struct hlist_node *n;
	struct fastrpc_mmap *map = 0;
	unsigned long flags;

	if (!fdata)
		return 0;

	(void)fastrpc_release_current_dsp_process(fdata);
	do {
		ctxfree = 0;
		write_lock_irqsave(&clst->lock, flags);
		hlist_for_each_entry_safe(ictx, n, &clst->interrupted, hn) {
			if (ictx->tgid == current->tgid) {
				hlist_del(&ictx->hn);
				ctxfree = ictx;
				break;
			}
		}
		write_unlock_irqrestore(&clst->lock, flags);
		if (ctxfree)
			context_free(ctxfree, 0);
	} while (ctxfree);

	cleanup_current_dev(fdata);
	file->private_data = 0;
	hlist_for_each_entry_safe(map, n, &fdata->hlst, hn) {
		hlist_del(&map->hn);
		free_map(map);
	}
	kfree(fdata);
	return 0;
}

static int fastrpc_device_open(struct inode *inode, struct file *filp)
{
	int cid = MINOR(inode->i_rdev);
	int err = 0;

	filp->private_data = 0;
	if (try_module_get(THIS_MODULE) != 0) {
		struct file_data *fdata = 0;
		/* This call will cause a dev to be created
		 * which will addref this module
		 */
		VERIFY(err, 0 != (fdata = kzalloc(sizeof(*fdata), GFP_KERNEL)));
		if (err)
			goto bail;

		spin_lock_init(&fdata->hlock);
		INIT_HLIST_HEAD(&fdata->hlst);
		fdata->cid = cid;
		fdata->tgid = current->tgid;

		filp->private_data = fdata;
bail:
		if (err) {
			if (fdata) {
				cleanup_current_dev(fdata);
				kfree(fdata);
			}
		}
		module_put(THIS_MODULE);
	}
	return err;
}

static long fastrpc_device_ioctl(struct file *file, unsigned int ioctl_num,
				 unsigned long ioctl_param)
{
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd invokefd;
	struct fastrpc_ioctl_mmap mmap;
	struct fastrpc_ioctl_munmap munmap;
	struct fastrpc_ioctl_init init;
	void *param = (char *)ioctl_param;
	struct file_data *fdata = (struct file_data *)file->private_data;
	int size = 0, err = 0;

	switch (ioctl_num) {
	case FASTRPC_IOCTL_INVOKE_FD:
	case FASTRPC_IOCTL_INVOKE:
		invokefd.fds = 0;
		size = (ioctl_num == FASTRPC_IOCTL_INVOKE) ?
				sizeof(invokefd.inv) : sizeof(invokefd);
		VERIFY(err, 0 == copy_from_user(&invokefd, param, size));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_invoke(me, fdata->mode,
						0, &invokefd, fdata)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MMAP:
		VERIFY(err, 0 == copy_from_user(&mmap, param,
						sizeof(mmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_mmap(me, fdata,
							      &mmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == copy_to_user(param, &mmap, sizeof(mmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MUNMAP:
		VERIFY(err, 0 == copy_from_user(&munmap, param,
						sizeof(munmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_munmap(me, fdata,
								&munmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_SETMODE:
		switch ((uint32_t)ioctl_param) {
		case FASTRPC_MODE_PARALLEL:
		case FASTRPC_MODE_SERIAL:
			fdata->mode = (uint32_t)ioctl_param;
			break;
		default:
			err = -ENOTTY;
			break;
		}
		break;
	case FASTRPC_IOCTL_INIT:
		VERIFY(err, 0 == copy_from_user(&init, param,
						sizeof(init)));
		if (err)
			goto bail;
		VERIFY(err, 0 == fastrpc_init_process(fdata, &init));
		if (err)
			goto bail;
		break;

	default:
		err = -ENOTTY;
		break;
	}
 bail:
	return err;
}

static void qcom_smd_fastrpc_remove(struct qcom_smd_device *dev)
{
	struct fastrpc_apps *me = &gfa;

	context_notify_all_users(&me->clst);
}

static int qcom_smd_fastrpc_probe(struct qcom_smd_device *dev)
{
	struct fastrpc_apps *me = &gfa;

	of_dma_configure_ops(&dev->dev, dev->dev.of_node);
	me->qsdev = dev;
	return 0;
}

static int qcom_smd_fastrpc_callback(struct qcom_smd_device *dev,
					const void *data,
					size_t count)
{
	struct smq_invoke_rsp *rsp = (struct smq_invoke_rsp *)data;
	int err = 0;

	VERIFY(err, count >= sizeof(*rsp));
	if (err)
		goto bail;
	context_notify_user(rsp->pid, rsp->tid, rsp->retval);
bail:
	return err;
}

static const struct of_device_id qcom_smd_fastrpc_of_match[] = {
	{ .compatible = "qcom,fastrpc" },
	{}
};
MODULE_DEVICE_TABLE(of, qcom_smd_fastrpc_of_match);

static struct qcom_smd_driver qcom_smd_fastrpc_driver = {
	.probe = qcom_smd_fastrpc_probe,
	.remove = qcom_smd_fastrpc_remove,
	.callback = qcom_smd_fastrpc_callback,
	.driver  = {
		.name  = "qcom_smd_fastrpc",
		.owner = THIS_MODULE,
		.of_match_table = qcom_smd_fastrpc_of_match,
	},
};

static const struct file_operations fops = {
	.open = fastrpc_device_open,
	.release = fastrpc_device_release,
	.unlocked_ioctl = fastrpc_device_ioctl,
	.compat_ioctl = compat_fastrpc_device_ioctl,
};

static int __init fastrpc_device_init(void)
{
	struct fastrpc_apps *me = &gfa;
	int err = 0;

	memset(me, 0, sizeof(*me));
	VERIFY(err, 0 == fastrpc_init());
	if (err)
		goto fastrpc_bail;
	VERIFY(err, 0 == alloc_chrdev_region(&me->dev_no, 0, 1,
					DEVICE_NAME));
	if (err)
		goto alloc_chrdev_bail;
	cdev_init(&me->cdev, &fops);
	me->cdev.owner = THIS_MODULE;
	VERIFY(err, 0 == cdev_add(&me->cdev, MKDEV(MAJOR(me->dev_no), 0),
				1));
	if (err)
		goto cdev_init_bail;
	me->class = class_create(THIS_MODULE, "fastrpc");
	VERIFY(err, !IS_ERR(me->class));
	if (err)
		goto class_create_bail;
	me->compat = (fops.compat_ioctl == NULL) ? 0 : 1;
	me->dev = device_create(me->class, NULL,
				MKDEV(MAJOR(me->dev_no), 0),
				NULL, "adsprpc-smd");
	VERIFY(err, !IS_ERR(me->dev));
	if (err)
		goto device_create_bail;

	qcom_smd_driver_register(&qcom_smd_fastrpc_driver);
	return 0;

device_create_bail:
	class_destroy(me->class);
class_create_bail:
	cdev_del(&me->cdev);
cdev_init_bail:
	unregister_chrdev_region(me->dev_no, 1);
alloc_chrdev_bail:
	fastrpc_deinit();
fastrpc_bail:
	return err;
}

static void __exit fastrpc_device_exit(void)
{
	struct fastrpc_apps *me = &gfa;

	context_list_dtor(me, &me->clst);
	fastrpc_deinit();
}

late_initcall(fastrpc_device_init);
module_exit(fastrpc_device_exit);

MODULE_LICENSE("GPL v2");
