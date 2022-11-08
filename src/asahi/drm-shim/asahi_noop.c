/*
 * Copyright (C) 2022 Alyssa Rosenzweig
 * Copyright © 2018 Broadcom
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "drm-shim/drm_shim.h"
#include "drm-uapi/asahi_drm.h"
#include "asahi/lib/agx_pack.h"

bool drm_shim_driver_prefers_first_render_node = true;

struct asahi_bo {
   struct shim_bo base;
   uint32_t offset;
};

static struct asahi_bo *
asahi_bo(struct shim_bo *bo)
{
   return (struct asahi_bo *)bo;
}

struct asahi_device {
   uint64_t next_offset;
};

static struct asahi_device asahi = {
   .next_offset = 0x1000,
};

static int
asahi_ioctl_noop(int fd, unsigned long request, void *arg)
{
   return 0;
}

static int
asahi_ioctl_submit(int fd, unsigned long request, void *arg)
{
   struct drm_asahi_submit *submit = arg;
   const void *cmdbuf = (void *) (uintptr_t) submit->cmdbuf;

   struct AGX_IOGPU_HEADER header;

   AGX_IOGPU_HEADER_unpack(stderr, cmdbuf, &header);

   printf("Encoder: %" PRIx64 "\n", header.encoder);

   // Lina: Your code goes here!

   return 0;
}

static int
asahi_ioctl_create_bo(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   struct drm_asahi_create_bo *create = arg;
   struct asahi_bo *bo = calloc(1, sizeof(*bo));

   drm_shim_bo_init(&bo->base, create->size);

   assert(UINT64_MAX - asahi.next_offset > create->size);
   bo->offset = asahi.next_offset;
   asahi.next_offset += create->size;

   create->offset = bo->offset;
   create->handle = drm_shim_bo_get_handle(shim_fd, &bo->base);

   drm_shim_bo_put(&bo->base);

   return 0;
}

static int
asahi_ioctl_get_bo_offset(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   struct drm_asahi_get_bo_offset *args = arg;
   struct shim_bo *bo = drm_shim_bo_lookup(shim_fd, args->handle);

   args->offset = asahi_bo(bo)->offset;

   drm_shim_bo_put(bo);

   return 0;
}

static int
asahi_ioctl_mmap_bo(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   struct drm_asahi_mmap_bo *map = arg;
   struct shim_bo *bo = drm_shim_bo_lookup(shim_fd, map->handle);

   map->offset = drm_shim_bo_get_mmap_offset(shim_fd, bo);

   drm_shim_bo_put(bo);

   return 0;
}

static int
asahi_ioctl_get_param(int fd, unsigned long request, void *arg)
{
   struct drm_asahi_get_param *gp = arg;

   switch (gp->param) {
      default:
         fprintf(stderr, "Unknown DRM_IOCTL_ASAHI_GET_PARAM %d\n", gp->param);
         return -1;
   }
}

static ioctl_fn_t driver_ioctls[] = {
   [DRM_ASAHI_SUBMIT] = asahi_ioctl_submit,
   [DRM_ASAHI_WAIT] = asahi_ioctl_noop,
   [DRM_ASAHI_CREATE_BO] = asahi_ioctl_create_bo,
   [DRM_ASAHI_MMAP_BO] = asahi_ioctl_mmap_bo,
   [DRM_ASAHI_GET_PARAM] = asahi_ioctl_get_param,
   [DRM_ASAHI_GET_BO_OFFSET] = asahi_ioctl_get_bo_offset,
};

void
drm_shim_driver_init(void)
{
   shim_device.bus_type = DRM_BUS_PLATFORM;
   shim_device.driver_name = "asahi";
   shim_device.driver_ioctls = driver_ioctls;
   shim_device.driver_ioctl_count = ARRAY_SIZE(driver_ioctls);

   drm_shim_override_file("DRIVER=asahi\n"
         "OF_FULLNAME=/soc/agx\n"
         "OF_COMPATIBLE_0=apple,gpu-g13g\n"
         "OF_COMPATIBLE_N=1\n",
         "/sys/dev/char/%d:%d/device/uevent", DRM_MAJOR,
         render_node_minor);
}
