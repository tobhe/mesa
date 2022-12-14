/*
 * Copyright (C) 2021 Alyssa Rosenzweig <alyssa@rosenzweig.io>
 * Copyright 2019 Collabora, Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <inttypes.h>
#include "agx_device.h"
#include "agx_bo.h"
#include "decode.h"

#ifndef __APPLE__
#include <fcntl.h>
#include <xf86drm.h>
#include "drm-uapi/asahi_drm.h"
#include "util/os_mman.h"
#endif

static void
agx_bo_free(struct agx_device *dev, struct agx_bo *bo)
{
   const uint64_t handle = bo->handle;

#if __APPLE__
   kern_return_t ret = IOConnectCallScalarMethod(dev->fd,
                       AGX_SELECTOR_FREE_MEM,
                       &handle, 1, NULL, NULL);

   if (ret)
      fprintf(stderr, "error freeing BO mem: %u\n", ret);
#else
   if (bo->ptr.cpu)
      munmap(bo->ptr.cpu, bo->size);
   struct drm_gem_close args = { .handle = handle };
   drmIoctl(dev->fd, DRM_IOCTL_GEM_CLOSE, &args);
#endif

   /* Reset the handle */
   memset(bo, 0, sizeof(*bo));
}

#if __APPLE__
void
agx_shmem_free(struct agx_device *dev, unsigned handle)
{
	const uint64_t input = handle;
   kern_return_t ret = IOConnectCallScalarMethod(dev->fd,
                       AGX_SELECTOR_FREE_SHMEM,
                       &input, 1, NULL, NULL);

   if (ret)
      fprintf(stderr, "error freeing shmem: %u\n", ret);
}

struct agx_bo
agx_shmem_alloc(struct agx_device *dev, size_t size, bool cmdbuf)
{
   struct agx_bo bo;

   struct agx_create_shmem_resp out = {};
   size_t out_sz = sizeof(out);

   uint64_t inputs[2] = {
      size,
      cmdbuf ? 1 : 0 // 2 - error reporting, 1 - no error reporting
   };

   kern_return_t ret = IOConnectCallMethod(dev->fd,
                                           AGX_SELECTOR_CREATE_SHMEM, inputs, 2, NULL, 0, NULL,
                                           NULL, &out, &out_sz);

   assert(ret == 0);
   assert(out_sz == sizeof(out));
   assert(out.size == size);
   assert(out.map != 0);

   bo = (struct agx_bo) {
      .type = cmdbuf ? AGX_ALLOC_CMDBUF : AGX_ALLOC_MEMMAP,
      .handle = out.id,
      .ptr.cpu = out.map,
      .size = out.size,
   };

   if (dev->debug & AGX_DBG_TRACE)
      agxdecode_track_alloc(&bo);

   return bo;
}
#endif

#ifndef __APPLE__
void
agx_bo_mmap(struct agx_bo *bo)
{
   struct drm_asahi_mmap_bo mmap_bo = { .handle = bo->handle };
   int ret;

   if (bo->ptr.cpu)
      return;

   ret = drmIoctl(bo->dev->fd, DRM_IOCTL_ASAHI_MMAP_BO, &mmap_bo);
   if (ret) {
      fprintf(stderr, "DRM_IOCTL_ASAHI_MMAP_BO failed: %m\n");
      assert(0);
   }

   bo->ptr.cpu = os_mmap(NULL, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
         bo->dev->fd, mmap_bo.offset);
   if (bo->ptr.cpu == MAP_FAILED) {
      bo->ptr.cpu = NULL;
      fprintf(stderr,
            "mmap failed: result=%p size=0x%llx fd=%i offset=0x%llx %m\n",
            bo->ptr.cpu, (long long)bo->size, bo->dev->fd,
            (long long)mmap_bo.offset);
   }
}

#endif

static struct agx_bo *
agx_bo_alloc(struct agx_device *dev, size_t size,
             uint32_t flags)
{
   struct agx_bo *bo;
   unsigned handle = 0;

#if __APPLE__
   uint32_t mode = 0x430; // shared, ?

   uint32_t args_in[24] = { 0 };
   args_in[4] = 0x4000101; //0x1000101; // unk
   args_in[5] = mode;
   args_in[16] = size;
   args_in[20] = flags;

   uint64_t out[10] = { 0 };
   size_t out_sz = sizeof(out);

   kern_return_t ret = IOConnectCallMethod(dev->fd,
                                           AGX_SELECTOR_ALLOCATE_MEM, NULL, 0, args_in,
                                           sizeof(args_in), NULL, 0, out, &out_sz);

   assert(ret == 0);
   assert(out_sz == sizeof(out));
   handle = (out[3] >> 32ull);
#else
   struct drm_asahi_create_bo create_bo = {
      .size = size
   };

   switch (flags) {
      case AGX_MEMORY_TYPE_NORMAL:
      case AGX_MEMORY_TYPE_FRAMEBUFFER:
         create_bo.flags = 0;
         break;

      case AGX_MEMORY_TYPE_SHADER:
      case AGX_MEMORY_TYPE_CMDBUF_32:
         create_bo.flags = ASAHI_BO_PIPELINE;
         break;
   }

   int ret = drmIoctl(dev->fd, DRM_IOCTL_ASAHI_CREATE_BO, &create_bo);
   if (ret) {
      fprintf(stderr, "DRM_IOCTL_ASAHI_CREATE_BO failed: %m\n");
      return NULL;
   }

   handle = create_bo.handle;
#endif

   pthread_mutex_lock(&dev->bo_map_lock);
   bo = agx_lookup_bo(dev, handle);
   pthread_mutex_unlock(&dev->bo_map_lock);

   /* Fresh handle */
   assert(!memcmp(bo, &((struct agx_bo) {}), sizeof(*bo)));

   bo->type = AGX_ALLOC_REGULAR;
   bo->size = size;
   bo->flags = flags;
   bo->dev = dev;
   bo->handle = handle;

   ASSERTED bool lo = (flags & 0x08000000);

#if __APPLE__
   bo->ptr.gpu = out[0];
   bo->ptr.cpu = (void *) out[1];
   bo->guid = out[5];
#else
   bo->ptr.gpu = create_bo.offset;
   bo->guid = bo->handle; /* TODO: We don't care about guids */

   agx_bo_mmap(bo);
#endif

   assert(bo->ptr.gpu < (1ull << (lo ? 32 : 40)));

   return bo;
}

/* Helper to calculate the bucket index of a BO */
static unsigned
agx_bucket_index(unsigned size)
{
   /* Round down to POT to compute a bucket index */
   unsigned bucket_index = util_logbase2(size);

   /* Clamp to supported buckets. Huge allocations use the largest bucket */
   bucket_index = CLAMP(bucket_index, MIN_BO_CACHE_BUCKET, MAX_BO_CACHE_BUCKET);

   /* Reindex from 0 */
   return (bucket_index - MIN_BO_CACHE_BUCKET);
}

static struct list_head *
agx_bucket(struct agx_device *dev, unsigned size)
{
   return &dev->bo_cache.buckets[agx_bucket_index(size)];
}

static bool
agx_bo_wait(struct agx_bo *bo, int64_t timeout_ns)
{
   /* TODO: When we allow parallelism we'll need to implement this for real */
   return true;
}

static void
agx_bo_cache_remove_locked(struct agx_device *dev, struct agx_bo *bo)
{
   simple_mtx_assert_locked(&dev->bo_cache.lock);
   list_del(&bo->bucket_link);
   list_del(&bo->lru_link);
   dev->bo_cache.size -= bo->size;
}

/* Tries to fetch a BO of sufficient size with the appropriate flags from the
 * BO cache. If it succeeds, it returns that BO and removes the BO from the
 * cache. If it fails, it returns NULL signaling the caller to allocate a new
 * BO. */

static struct agx_bo *
agx_bo_cache_fetch(struct agx_device *dev, size_t size, uint32_t flags, const
                   bool dontwait)
{
   simple_mtx_lock(&dev->bo_cache.lock);
   struct list_head *bucket = agx_bucket(dev, size);
   struct agx_bo *bo = NULL;

   /* Iterate the bucket looking for something suitable */
   list_for_each_entry_safe(struct agx_bo, entry, bucket, bucket_link) {
      if (entry->size < size || entry->flags != flags)
         continue;

      /* If the oldest BO in the cache is busy, likely so is
       * everything newer, so bail. */
      if (!agx_bo_wait(entry, dontwait ? 0 : INT64_MAX))
         break;

      /* This one works, use it */
      agx_bo_cache_remove_locked(dev, entry);
      bo = entry;
      break;
   }
   simple_mtx_unlock(&dev->bo_cache.lock);

   return bo;
}

static void
agx_bo_cache_evict_stale_bos(struct agx_device *dev)
{
   struct timespec time;

   clock_gettime(CLOCK_MONOTONIC, &time);
   list_for_each_entry_safe(struct agx_bo, entry,
         &dev->bo_cache.lru, lru_link) {
      /* We want all entries that have been used more than 1 sec ago to be
       * dropped, others can be kept.  Note the <= 2 check and not <= 1. It's
       * here to account for the fact that we're only testing ->tv_sec, not
       * ->tv_nsec.  That means we might keep entries that are between 1 and 2
       * seconds old, but we don't really care, as long as unused BOs are
       * dropped at some point.
       */
      if (time.tv_sec - entry->last_used <= 2)
         break;

      agx_bo_cache_remove_locked(dev, entry);
      agx_bo_free(dev, entry);
   }
}

static void
agx_bo_cache_put_locked(struct agx_bo *bo)
{
   struct agx_device *dev = bo->dev;
   struct list_head *bucket = agx_bucket(dev, bo->size);
   struct timespec time;

   /* Add us to the bucket */
   list_addtail(&bo->bucket_link, bucket);

   /* Add us to the LRU list and update the last_used field. */
   list_addtail(&bo->lru_link, &dev->bo_cache.lru);
   clock_gettime(CLOCK_MONOTONIC, &time);
   bo->last_used = time.tv_sec;

   /* Update statistics */
   dev->bo_cache.size += bo->size;

   if (0) {
      printf("BO cache: %zu KiB (+%zu KiB from %s, hit/miss %" PRIu64 "/%" PRIu64 ")\n",
             DIV_ROUND_UP(dev->bo_cache.size, 1024),
             DIV_ROUND_UP(bo->size, 1024),
             bo->label,
             dev->bo_cache.hits,
             dev->bo_cache.misses);
   }

   /* Update label for debug */
   bo->label = "Unused (BO cache)";

   /* Let's do some cleanup in the BO cache while we hold the lock. */
   agx_bo_cache_evict_stale_bos(dev);
}

/* Tries to add a BO to the cache. Returns if it was successful */
static bool
agx_bo_cache_put(struct agx_bo *bo)
{
   struct agx_device *dev = bo->dev;

   if (bo->flags & AGX_BO_SHARED) {
      return false;
   } else {
      simple_mtx_lock(&dev->bo_cache.lock);
      agx_bo_cache_put_locked(bo);
      simple_mtx_unlock(&dev->bo_cache.lock);

      return true;
   }
}

static void
agx_bo_cache_evict_all(struct agx_device *dev)
{
   simple_mtx_lock(&dev->bo_cache.lock);
   for (unsigned i = 0; i < ARRAY_SIZE(dev->bo_cache.buckets); ++i) {
      struct list_head *bucket = &dev->bo_cache.buckets[i];

      list_for_each_entry_safe(struct agx_bo, entry, bucket,
            bucket_link) {
         agx_bo_cache_remove_locked(dev, entry);
         agx_bo_free(dev, entry);
      }
   }
   simple_mtx_unlock(&dev->bo_cache.lock);
}

void
agx_bo_reference(struct agx_bo *bo)
{
   if (bo) {
      ASSERTED int count = p_atomic_inc_return(&bo->refcnt);
      assert(count != 1);
   }
}

void
agx_bo_unreference(struct agx_bo *bo)
{
   if (!bo)
      return;

   /* Don't return to cache if there are still references */
   if (p_atomic_dec_return(&bo->refcnt))
      return;

   struct agx_device *dev = bo->dev;

   pthread_mutex_lock(&dev->bo_map_lock);

   /* Someone might have imported this BO while we were waiting for the
    * lock, let's make sure it's still not referenced before freeing it.
    */
   if (p_atomic_read(&bo->refcnt) == 0) {
      if (dev->debug & AGX_DBG_TRACE)
         agxdecode_track_free(bo);

      if (!agx_bo_cache_put(bo))
         agx_bo_free(dev, bo);
   }

   pthread_mutex_unlock(&dev->bo_map_lock);
}

struct agx_bo *
agx_bo_import(struct agx_device *dev, int fd)
{
#ifndef __APPLE__
   struct agx_bo *bo;
   struct drm_asahi_get_bo_offset get_bo_offset = {0,};
   ASSERTED int ret;
   unsigned gem_handle;

   ret = drmPrimeFDToHandle(dev->fd, fd, &gem_handle);
   assert(!ret);

   pthread_mutex_lock(&dev->bo_map_lock);
   bo = agx_lookup_bo(dev, gem_handle);

   if (!bo->dev) {
      get_bo_offset.handle = gem_handle;
      ret = drmIoctl(dev->fd, DRM_IOCTL_ASAHI_GET_BO_OFFSET, &get_bo_offset);
      assert(!ret);

      bo->dev = dev;
      bo->ptr.gpu = get_bo_offset.offset;
      bo->size = lseek(fd, 0, SEEK_END);
      /* Sometimes this can fail and return -1. size of -1 is not
      * a nice thing for mmap to try mmap. Be more robust also
      * for zero sized maps and fail nicely too
      */
      if ((bo->size == 0) || (bo->size == (size_t)-1)) {
            pthread_mutex_unlock(&dev->bo_map_lock);
            return NULL;
      }
      bo->flags = AGX_BO_SHARED;
      bo->handle = gem_handle;
      p_atomic_set(&bo->refcnt, 1);
   } else {
      /* bo->refcnt == 0 can happen if the BO
      * was being released but agx_bo_import() acquired the
      * lock before agx_bo_unreference(). In that case, refcnt
      * is 0 and we can't use agx_bo_reference() directly, we
      * have to re-initialize the refcnt().
      * Note that agx_bo_unreference() checks
      * refcnt value just after acquiring the lock to
      * make sure the object is not freed if agx_bo_import()
      * acquired it in the meantime.
      */
      if (p_atomic_read(&bo->refcnt) == 0)
         p_atomic_set(&bo->refcnt, 1);
      else
         agx_bo_reference(bo);
   }
   pthread_mutex_unlock(&dev->bo_map_lock);

   return bo;
#else
   return NULL;
#endif
}

int
agx_bo_export(struct agx_bo *bo)
{
#ifndef __APPLE__
   int fd;

   if (drmPrimeHandleToFD(bo->dev->fd, bo->handle, DRM_CLOEXEC, &fd))
      return -1;

   bo->flags |= AGX_BO_SHARED;
   return fd;
#else
   return 0;
#endif
}

struct agx_bo *
agx_bo_create(struct agx_device *dev, unsigned size, unsigned flags,
              const char *label)
{
   struct agx_bo *bo;
   assert(size > 0);

   /* To maximize BO cache usage, don't allocate tiny BOs */
   size = ALIGN_POT(size, 16384);

   /* See if we have a BO already in the cache */
   bo = agx_bo_cache_fetch(dev, size, flags, true);

   /* Update stats based on the first attempt to fetch */
   if (bo != NULL)
      dev->bo_cache.hits++;
   else
      dev->bo_cache.misses++;

   /* Otherwise, allocate a fresh BO. If allocation fails, we can try waiting
    * for something in the cache. But if there's no nothing suitable, we should
    * flush the cache to make space for the new allocation.
    */
   if (!bo)
      bo = agx_bo_alloc(dev, size, flags);
   if (!bo)
      bo = agx_bo_cache_fetch(dev, size, flags, false);
   if (!bo) {
      agx_bo_cache_evict_all(dev);
      bo = agx_bo_alloc(dev, size, flags);
   }

   if (!bo) {
      fprintf(stderr, "BO creation failed\n");
      return NULL;
   }

   bo->label = label;
   p_atomic_set(&bo->refcnt, 1);

   if (dev->debug & AGX_DBG_TRACE)
      agxdecode_track_alloc(bo);

   return bo;
}

static void
agx_get_global_ids(struct agx_device *dev)
{
#if __APPLE__
   uint64_t out[2] = {};
   size_t out_sz = sizeof(out);

   ASSERTED kern_return_t ret = IOConnectCallStructMethod(dev->fd,
                       AGX_SELECTOR_GET_GLOBAL_IDS,
                       NULL, 0, &out, &out_sz);

   assert(ret == 0);
   assert(out_sz == sizeof(out));
   assert(out[1] > out[0]);

   dev->next_global_id = out[0];
   dev->last_global_id = out[1];
#else
   dev->next_global_id = 0;
   dev->last_global_id = 0x1000000;
#endif
}

uint64_t
agx_get_global_id(struct agx_device *dev)
{
   if (unlikely(dev->next_global_id >= dev->last_global_id)) {
      agx_get_global_ids(dev);
   }

   return dev->next_global_id++;
}

#ifdef __APPLE__
/* Tries to open an AGX device, returns true if successful */

const char *services[] = {
   "AGXAcceleratorG13G_A0",
   "AGXAcceleratorG13G_B0",
   "AGXAcceleratorG13S_A0",
   "AGXAcceleratorG13X",
   "AGXAcceleratorG14G_A0",
   "AGXAcceleratorG14G",

};

const agx_device_id agx_device_ids[] = {
   { .generation = 13, .variant = 'G', .revision = DRM_ASAHI_REV_A0 },
   { .generation = 13, .variant = 'G', .revision = DRM_ASAHI_REV_B0 },
   { .generation = 13, .variant = 'S', .revision = DRM_ASAHI_REV_A0 },
   // TODO: Can we get the real revision on macOS?
   { .generation = 13, .variant = 'X', .revision = DRM_ASAHI_REV_B0 },
   { .generation = 14, .variant = 'G', .revision = DRM_ASAHI_REV_A0 },
   { .generation = 14, .variant = 'G', .revision = DRM_ASAHI_REV_B0 },
};

#endif

#ifndef __APPLE__
static bool
agx_get_param(struct agx_device *dev, uint32_t param, uint64_t *value) {
   struct drm_asahi_get_param get_param = {
      .param = param,
   };

   int ret = drmIoctl(dev->fd, DRM_IOCTL_ASAHI_GET_PARAM, &get_param);
   if (ret) {
      fprintf(stderr, "DRM_IOCTL_ASAHI_GET_PARAM(%d) failed: %m\n", param);
      return false;
   }
   *value = get_param.value;
   return true;
}
#endif

bool
agx_open_device(void *memctx, struct agx_device *dev)
{
#if __APPLE__
   kern_return_t ret;
   io_service_t service;
   int i;

   for (i = 0; i < ARRAY_SIZE(services); i++) {
      CFDictionaryRef matching = IOServiceNameMatching(services[i]);
      service = IOServiceGetMatchingService(0, matching);
      if (service) {
         dev->id = agx_device_ids[i];
         break;
      }
   }

   if (!service)
      return false;

   ret = IOServiceOpen(service, mach_task_self(), AGX_SERVICE_TYPE, &dev->fd);

   if (ret)
      return false;

   const char *api = "Equestria";
   char in[16] = { 0 };
   assert(strlen(api) < sizeof(in));
   memcpy(in, api, strlen(api));

   ret = IOConnectCallStructMethod(dev->fd, AGX_SELECTOR_SET_API, in,
                                   sizeof(in), NULL, NULL);

   /* Oddly, the return codes are flipped for SET_API */
   if (ret != 1)
      return false;
#else
   uint64_t val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_UNSTABLE_UABI_VERSION, &val)) {
      assert(0);
      return false;
   }

   if (val != DRM_ASAHI_UNSTABLE_UABI_VERSION) {
      fprintf(stderr, "UABI mismatch: Kernel %ld, Mesa %d\n",
              val, DRM_ASAHI_UNSTABLE_UABI_VERSION);
      assert(0);
      return false;
   }

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_GPU_GENERATION, &val)) {
      assert(0);
      return false;
   }
   dev->id.generation = val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_GPU_VARIANT, &val)) {
      assert(0);
      return false;
   }
   dev->id.variant = val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_GPU_REVISION, &val)) {
      assert(0);
      return false;
   }
   dev->id.revision = val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_CHIP_ID, &val)) {
      assert(0);
      return false;
   }
   dev->id.chip_id = val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_FEAT_COMPAT, &val)) {
      assert(0);
      return false;
   }
   dev->id.feat_compat = val;

   if (!agx_get_param(dev, DRM_ASAHI_PARAM_FEAT_INCOMPAT, &val)) {
      assert(0);
      return false;
   }
   dev->id.feat_incompat = val;

   uint64_t incompat = val & (~AGX_SUPPORTED_INCOMPAT_FEATURES);
   if (incompat) {
      fprintf(stderr, "Missing GPU incompat features: 0x%lx\n", incompat);
      assert(0);
      return false;
   }
   #endif

   if (dev->id.generation >= 13 && dev->id.variant != 'P') {
      const char *variant = " Unknown";
      switch (dev->id.variant) {
         case 'G': variant = ""; break;
         case 'S': variant = " Pro"; break;
         case 'C': variant = " Max"; break;
         case 'D': variant = " Ultra"; break;
      }
      snprintf(dev->id.name, sizeof(dev->id.name), "Apple M%d%s (G%d%c %s)",
               dev->id.generation - 12, variant, dev->id.generation, dev->id.variant,
               agx_get_revision_string(&dev->id));
   } else {
      // Note: untested, theoretically this is the logic for at least a few generations back.
      const char *variant = " Unknown";
      switch (dev->id.variant) {
         case 'P': variant = ""; break;
         case 'G': variant = "X"; break;
      }
      snprintf(dev->id.name, sizeof(dev->id.name), "Apple A%d%s (G%d%c %s)",
               dev->id.generation + 1, variant, dev->id.generation, dev->id.variant,
               agx_get_revision_string(&dev->id));
   }

   dev->memctx = memctx;
   util_sparse_array_init(&dev->bo_map, sizeof(struct agx_bo), 512);

   simple_mtx_init(&dev->bo_cache.lock, mtx_plain);
   list_inithead(&dev->bo_cache.lru);

   for (unsigned i = 0; i < ARRAY_SIZE(dev->bo_cache.buckets); ++i)
      list_inithead(&dev->bo_cache.buckets[i]);

   dev->queue = agx_create_command_queue(dev);
#if __APPLE__
   dev->cmdbuf = agx_shmem_alloc(dev, 0x4000, true); // length becomes kernelCommandDataSize
   dev->memmap = agx_shmem_alloc(dev, 0x10000, false);
#endif
   agx_get_global_ids(dev);

   return true;
}

void
agx_close_device(struct agx_device *dev)
{
   agx_bo_cache_evict_all(dev);
   util_sparse_array_finish(&dev->bo_map);

#if __APPLE__
   kern_return_t ret = IOServiceClose(dev->fd);

   if (ret)
      fprintf(stderr, "Error from IOServiceClose: %u\n", ret);
#endif
}

#if __APPLE__
static struct agx_notification_queue
agx_create_notification_queue(mach_port_t connection)
{
   struct agx_create_notification_queue_resp resp;
   size_t resp_size = sizeof(resp);
   assert(resp_size == 0x10);

   ASSERTED kern_return_t ret = IOConnectCallStructMethod(connection,
                       AGX_SELECTOR_CREATE_NOTIFICATION_QUEUE,
                       NULL, 0, &resp, &resp_size);

   assert(resp_size == sizeof(resp));
   assert(ret == 0);

   mach_port_t notif_port = IODataQueueAllocateNotificationPort();
   IOConnectSetNotificationPort(connection, 0, notif_port, resp.unk2);

   return (struct agx_notification_queue) {
      .port = notif_port,
      .queue = resp.queue,
      .id = resp.unk2
   };
}
#endif

struct agx_command_queue
agx_create_command_queue(struct agx_device *dev)
{
#if __APPLE__
   struct agx_command_queue queue = {};

   {
      uint8_t buffer[1024 + 8] = { 0 };
      const char *path = "/tmp/a.out";
      assert(strlen(path) < 1022);
      memcpy(buffer + 0, path, strlen(path));

      /* Copy to the end */
      unsigned END_LEN = MIN2(strlen(path), 1024 - strlen(path));
      unsigned SKIP = strlen(path) - END_LEN;
      unsigned OFFS = 1024 - END_LEN;
      memcpy(buffer + OFFS, path + SKIP, END_LEN);

      buffer[1024] = 0x2;

      struct agx_create_command_queue_resp out = {};
      size_t out_sz = sizeof(out);

      ASSERTED kern_return_t ret = IOConnectCallStructMethod(dev->fd,
                          AGX_SELECTOR_CREATE_COMMAND_QUEUE,
                          buffer, sizeof(buffer),
                          &out, &out_sz);

      assert(ret == 0);
      assert(out_sz == sizeof(out));

      queue.id = out.id;
      assert(queue.id);
   }

   queue.notif = agx_create_notification_queue(dev->fd);

   {
      uint64_t scalars[2] = {
         queue.id,
         queue.notif.id
      };

      ASSERTED kern_return_t ret = IOConnectCallScalarMethod(dev->fd,
                          0x1D,
                          scalars, 2, NULL, NULL);

      assert(ret == 0);
   }

   {
      uint64_t scalars[2] = {
         queue.id,
         0x1ffffffffull
      };

      ASSERTED kern_return_t ret = IOConnectCallScalarMethod(dev->fd,
                          0x31,
                          scalars, 2, NULL, NULL);

      assert(ret == 0);
   }

   return queue;
#else
   return (struct agx_command_queue) {
      0
   };
#endif
}

#if __APPLE__
void
agx_submit_cmdbuf(struct agx_device *dev, struct agx_bo *cmdbuf, unsigned mappings, uint64_t scalar)
{
   struct agx_submit_cmdbuf_req req = {
      .count = 1,
      .command_buffer_shmem_id = cmdbuf->handle,
      .segment_list_shmem_id = mappings,
      .notify_1 = 0xABCD,
      .notify_2 = 0x1234,
   };

   ASSERTED kern_return_t ret = IOConnectCallMethod(dev->fd,
                                           AGX_SELECTOR_SUBMIT_COMMAND_BUFFERS,
                                           &scalar, 1,
                                           &req, sizeof(req),
                                           NULL, 0, NULL, 0);
   assert(ret == 0);
   return;
}
#else
int
agx_submit_cmdbuf(struct agx_device *dev, struct drm_asahi_cmdbuf *c)
{
   struct drm_asahi_submit submit = {
      .cmdbuf = (uintptr_t) c
   };

   int ret = drmIoctl(dev->fd, DRM_IOCTL_ASAHI_SUBMIT, &submit);
   if (ret) {
      fprintf(stderr, "DRM_IOCTL_ASAHI_SUBMIT failed: %m (%dx%d tile %dx%d layers %d samples %d)\n",
              c->fb_width, c->fb_height, c->utile_width, c->utile_height,
              c->layers, c->samples);
      assert(0);
   }

   return ret;
}
#endif

/*
 * Wait for a frame to finish rendering.
 *
 * The macOS kernel indicates that rendering has finished using a notification
 * queue. The kernel will send two messages on the notification queue. The
 * second message indicates that rendering has completed. This simple routine
 * waits for both messages. It's important that IODataQueueDequeue is used in a
 * loop to flush the entire queue before calling
 * IODataQueueWaitForAvailableData. Otherwise, we can race and get stuck in
 * WaitForAvailabaleData.
 */
void
agx_wait_queue(struct agx_command_queue queue)
{
#if __APPLE__
   uint64_t data[4];
   unsigned sz = sizeof(data);
   unsigned message_id = 0;
   uint64_t magic_numbers[2] = { 0xABCD, 0x1234 };

   while (message_id < 2) {
      IOReturn ret = IODataQueueWaitForAvailableData(queue.notif.queue, queue.notif.port);

      if (ret) {
         fprintf(stderr, "Error waiting for available data\n");
         return;
      }

      while (IODataQueueDequeue(queue.notif.queue, data, &sz) == kIOReturnSuccess) {
         assert(sz == sizeof(data));
         assert(data[0] == magic_numbers[message_id]);
         message_id++;
      }
   }
#endif
}

const char *
agx_get_revision_string(const struct agx_device_id *id)
{
   switch (id->revision) {
      case 0x00: return "A0";
      case 0x01: return "A1";
      case 0x10: return "B0";
      case 0x11: return "B1";
      case 0x20: return "C0";
      case 0x21: return "C1";
   }

   return "Unknown";
}
