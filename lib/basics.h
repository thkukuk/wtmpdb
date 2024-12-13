// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _unused_(x) x __attribute__((unused))

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

static inline void freep(void *p) {
        *(void**)p = mfree(*(void**) p);
}

