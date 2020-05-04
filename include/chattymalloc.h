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

#include <stdint.h>		 // uint8_t
#include <sys/types.h> // pid_t

enum functions {
	UNINITIALIZED,
	MALLOC,
	FREE,
	REALLOC,
	CALLOC,
	MEMALIGN,
	POSIX_MEMALIGN,
	VALLOC,
	PVALLOC,
	ALIGNED_ALLOC,
	THREAD_TERMINATION
};

typedef struct trace {
	void *ptr;
	size_t size;
	size_t var_arg;
	pid_t tid;
	char func;
} __attribute__((packed)) trace_t;
