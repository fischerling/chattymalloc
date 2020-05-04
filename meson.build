project('chattymalloc', 'c',
		version : '0.1',
		default_options : [
		  'warning_level=3',
		  'c_std=gnu11',
		  'b_ndebug=if-release',
		  'werror=true',
		])

conf_data = configuration_data()

include_dir = include_directories('include')

thread_dep = dependency('threads')

cc = meson.get_compiler('c')
libdl = cc.find_library('dl')

chattymalloc_sources = ['chattymalloc.c']
chattymalloc_so = shared_library('chattymalloc',
								 chattymalloc_sources,
								 include_directories : include_dir,
								 c_args: ['-fno-builtin-calloc', '-fno-builtin-malloc'],
								 dependencies: [thread_dep, libdl])
