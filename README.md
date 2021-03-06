# chattymalloc - a high-performance shared library based malloc tracer

## Dependencies

* meson
* (clang-format, clang-tidy, yapf)

## Compilation

Clone the repository.
`git clone https://muhq.space/software/chattymalloc.git`

Build chattymalloc by running  `make` in the repository root.

## Usage

chattymalloc is designed to be used with the LD_PRELOAD mechanism.
It hooks the memory allocator API and saves each allocator call and its result
to a memory mapped binary file, called chattymalloc.trace, which will be stored to the current directory.

`env LD_PRELOAD=/path/to/libchattymalloc.so <your-binary>`

The resulting binary trace file can be parsed and the results plotted using
chattyparser.py.

# chattyparser - a parser and plotter for chattymalloc trace files

chattyparser parses a trace file, detects allocator and application misbehavior,
like double frees, produces a plain text trace, a histogram and a memory profile.

## Usage
	usage: chattyparser.py [-h] [--alignment ALIGNMENT ALIGNMENT] [--txt] [-v]
	                       [--license]
	                       trace

	parse and analyze chattymalloc traces

	positional arguments:
	  trace                 binary trace file created by chattymalloc

	optional arguments:
	  -h, --help            show this help message and exit
	  --alignment ALIGNMENT ALIGNMENT
	                        export to plain text format
	  --txt                 export to plain text format
	  -v, --verbose         more output
	  --license             print license info and exit
