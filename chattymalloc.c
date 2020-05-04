/*
Copyright 2018-2020 Florian Fischer <florian.fl.fischer@fau.de>

This file is part of chattymalloc.

chattymalloc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

chattymalloc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with chattymalloc.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include "chattymalloc.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define unlikely(x) __builtin_expect((x), 0)

#define BOOTSTRAP_MEMORY_SIZE 4096

#define GROWTH_THRESHOLD 4096
#define GROWTH_ENTRIES 100000

// flag to stop recursion during bootstrap
static int initializing = 0;

// memory to bootstrap malloc
static char tmpbuff[BOOTSTRAP_MEMORY_SIZE];
static unsigned long tmppos = 0;
static unsigned long tmpallocs = 0;

// global log file descriptor
static int out_fd = -1;
// memory mapping of our output file
static volatile trace_t *out[2] = {NULL, NULL};
// next free index into the mapped buffer
static volatile uint64_t next_entry = 0;
// current size of our log file / mapping
static volatile uint64_t total_entries = 0;

// pthread mutex and cond to protect growth of the buffer
static pthread_cond_t growing;
static pthread_mutex_t growth_mutex;

static __thread pid_t tid = 0;

// thread specific key to register a destructor
static pthread_key_t tls_key;
static pthread_once_t tls_key_once = PTHREAD_ONCE_INIT;

// log_thread_termination forward declaration because it uses trace_write
static void log_thread_termination(void *key __attribute__((unused)));

static void make_tls_key() {
	int err = pthread_key_create(&tls_key, log_thread_termination);
	if (err) {
		abort();
	}
}

static void init_thread() {
	tid = syscall(SYS_gettid);

	// init our thread destructor
	int err = pthread_once(&tls_key_once, make_tls_key);
	if (err) {
		abort();
	}

	// set the key to something != NULL to execute the destructor on thread exit
	// NOLINTNEXTLINE(readability-magic-numbers)
	err = pthread_setspecific(tls_key, (void *)42);
	if (err) {
		abort();
	}
}

/*=========================================================
 * intercepted functions
 */

static void *(*next_malloc)(size_t size);
static void (*next_free)(void *ptr);
static void *(*next_calloc)(size_t nmemb, size_t size);
static void *(*next_realloc)(void *ptr, size_t size);
static void *(*next_memalign)(size_t alignment, size_t size);
static int (*next_posix_memalign)(void **memptr, size_t alignment, size_t size);
static void *(*next_valloc)(size_t size);
static void *(*next_pvalloc)(size_t size);
static void *(*next_aligned_alloc)(size_t alignment, size_t size);
static int (*next_malloc_stats)();

static void grow_trace() {
	pthread_mutex_lock(&growth_mutex);

	size_t old_buf_idx;
	if (unlikely(total_entries == 0)) {
		old_buf_idx = 0;
	} else {
		old_buf_idx = ((total_entries) / GROWTH_ENTRIES) % 2;
	}
	size_t new_buf_size = (total_entries + GROWTH_ENTRIES) * sizeof(trace_t);

	/* remap old buffer
	 * hopefully no thread uses the old buffer anymore!
	 */
	if (out[old_buf_idx] == NULL) {
		out[old_buf_idx] =
				(trace_t *)mmap(NULL, new_buf_size, PROT_WRITE, MAP_FILE | MAP_SHARED, out_fd, 0);
		if (out[old_buf_idx] == MAP_FAILED) {
			perror("mapping new buf failed");
			abort();
		}
	} else {
		size_t old_buf_size = (total_entries - GROWTH_ENTRIES) * sizeof(trace_t);
		out[old_buf_idx] =
				(trace_t *)mremap((void *)out[old_buf_idx], old_buf_size, new_buf_size, MREMAP_MAYMOVE);
		if (out[old_buf_idx] == MAP_FAILED) {
			perror("remapping old buf failed");
			abort();
		}
	}

	if (ftruncate(out_fd, new_buf_size) != 0) {
		perror("extending file failed");
		abort();
	}

	total_entries += GROWTH_ENTRIES;
	pthread_cond_broadcast(&growing);
	pthread_mutex_unlock(&growth_mutex);
}

static void write_trace(char func, void *ptr, size_t size, size_t var_arg) {
	if (unlikely(tid == 0)) {
		init_thread();
	}

	uint64_t idx = __atomic_fetch_add(&next_entry, 1, __ATOMIC_SEQ_CST);
	if (idx == total_entries - GROWTH_THRESHOLD) {
		grow_trace();
		// wait for growth completion
	} else if (idx >= total_entries) {
		pthread_mutex_lock(&growth_mutex);
		while (idx >= total_entries) {
			pthread_cond_wait(&growing, &growth_mutex);
		}
		pthread_mutex_unlock(&growth_mutex);
	}

	volatile trace_t *trace = &out[(idx / GROWTH_ENTRIES) % 2][idx];

	trace->tid = tid;
	trace->func = func;
	trace->ptr = ptr;
	trace->size = size;
	trace->var_arg = var_arg;
}

static void log_thread_termination(void *key __attribute__((unused))) {
	write_trace(THREAD_TERMINATION, NULL, 0, 0);
}

static void trim_trace() {
	uint64_t cur_size = next_entry * sizeof(trace_t);
	if (ftruncate(out_fd, cur_size) != 0) {
		perror("trimming file failed");
	}
	close(out_fd);
}

static void __attribute__((constructor)) init() {
	initializing = 1;
	char *fname = getenv("CHATTYMALLOC_FILE");
	if (fname == NULL) {
		fname = "chattymalloc.trace";
	}

	out_fd = open(fname, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (out_fd == -1) {
		perror("opening output file");
		abort();
	}

	pthread_cond_init(&growing, NULL);
	pthread_mutex_init(&growth_mutex, NULL);

	// init trace buffer
	grow_trace();

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	next_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	next_free = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	next_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	next_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	next_memalign = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "memalign");
	next_posix_memalign = (int (*)(void **, size_t, size_t))dlsym(RTLD_NEXT, "posix_memalign");
	next_valloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "valloc");
	next_pvalloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "pvalloc");
	next_aligned_alloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "aligned_alloc");
	next_malloc_stats = (int (*)(void))dlsym(RTLD_NEXT, "malloc_stats");
#pragma GCC diagnostic pop

	if (!next_malloc || !next_free || !next_calloc || !next_realloc || !next_memalign) {
		fprintf(stderr, "Can't load core functions with `dlsym`: %s\n", dlerror());
		abort();
	}
	if (!next_posix_memalign) {
		fprintf(stderr, "Can't load posix_memalign with `dlsym`: %s\n", dlerror());
	}
	if (!next_valloc) {
		fprintf(stderr, "Can't load valloc with `dlsym`: %s\n", dlerror());
	}
	if (!next_pvalloc) {
		fprintf(stderr, "Can't load pvalloc with `dlsym`: %s\n", dlerror());
	}
	if (!next_aligned_alloc) {
		fprintf(stderr, "Can't load aligned_alloc with `dlsym`: %s\n", dlerror());
	}
	if (!next_malloc_stats) {
		fprintf(stderr, "Can't load malloc_stats with `dlsym`: %s\n", dlerror());
	}

	atexit(trim_trace);
	initializing = 0;
}

void *malloc(size_t size) {
	if (unlikely(next_malloc == NULL)) {
		if (!initializing) {
			init();

		} else {
			void *retptr = tmpbuff + tmppos;
			tmppos += size;
			++tmpallocs;

			if (tmppos < sizeof(tmpbuff)) {
				return retptr;
			}

			fprintf(stderr, "%ld in %ld allocs\n", tmppos, tmpallocs);
			fprintf(stderr, "jcheck: too much memory requested during initialisation - "
											"increase tmpbuff size\n");
			abort();
		}
	}

	void *ptr = next_malloc(size);
	write_trace(MALLOC, ptr, size, 0);
	return ptr;
}

void free(void *ptr) {
	// something wrong if we call free before one of the allocators!
	if (unlikely(next_malloc == NULL)) {
		init();
	}

	if (!(ptr >= (void *)tmpbuff && ptr <= (void *)(tmpbuff + tmppos))) {
		write_trace(FREE, ptr, 0, 0);
		next_free(ptr);
	}
}

void *realloc(void *ptr, size_t size) {
	if (unlikely(next_realloc == NULL)) {
		void *nptr = malloc(size);
		if (nptr && ptr) {
			// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
			memmove(nptr, ptr, size);
			free(ptr);
		}
		return nptr;
	}

	void *nptr = next_realloc(ptr, size);
	write_trace(REALLOC, nptr, size, (size_t)ptr);
	return nptr;
}

void *calloc(size_t nmemb, size_t size) {
	if (unlikely(next_calloc == NULL)) {
		void *ptr = malloc(nmemb * size);
		if (ptr) {
			// NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
			memset(ptr, 0, nmemb * size);
		}
		return ptr;
	}

	void *ptr = next_calloc(nmemb, size);
	write_trace(CALLOC, ptr, size, nmemb);
	return ptr;
}

void *memalign(size_t alignment, size_t size) {
	if (unlikely(next_memalign == NULL)) {
		fprintf(stderr, "called memalign before or during init\n");
		abort();
	}

	void *ptr = next_memalign(alignment, size);
	write_trace(MEMALIGN, ptr, size, alignment);
	return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
	if (unlikely(next_posix_memalign == NULL)) {
		fprintf(stderr, "called posix_memalign before or during init\n");
		abort();
	}

	int ret = next_posix_memalign(memptr, alignment, size);
	write_trace(POSIX_MEMALIGN, *memptr, size, alignment);
	return ret;
}

void *valloc(size_t size) {
	if (unlikely(next_valloc == NULL)) {
		fprintf(stderr, "called valloc before or during init");
		abort();
	}

	void *ptr = next_valloc(size);
	write_trace(VALLOC, ptr, size, 0);
	return ptr;
}

void *pvalloc(size_t size) {
	if (unlikely(next_pvalloc == NULL)) {
		fprintf(stderr, "called pvalloc before or during init\n");
		abort();
	}

	void *ptr = next_pvalloc(size);
	write_trace(PVALLOC, ptr, size, 0);
	return ptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
	if (next_aligned_alloc == NULL) {
		fprintf(stderr, "called aligned_alloc before or during init\n");
		abort();
	}

	void *ptr = next_aligned_alloc(alignment, size);
	write_trace(ALIGNED_ALLOC, ptr, size, alignment);
	return ptr;
}

int malloc_stats() {
	if (unlikely(next_malloc_stats == NULL)) {
		fprintf(stderr, "called malloc_stats before or during init\n");
		abort();
	}

	fprintf(stderr, "chattymalloc by muhq\n");
	return next_malloc_stats();
}
