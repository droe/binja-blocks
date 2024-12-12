# Apple Blocks Plugin
Author: Daniel Roethlisberger

Annotation of Apple [libclosure](https://github.com/apple-oss-distributions/libclosure) [blocks](https://clang.llvm.org/docs/BlockLanguageSpec.html).

## Description

Type annotation of stack and global blocks, block descriptors, variables closed
over and related function signatures in [Binary Ninja](https://binary.ninja/).
Blocks are an implementation of closures often found in C, C++, ObjC and ObjC++
code for Apple platforms.  Blocks are not the same as C++ lambdas.

Stack block before annotation:

![Screenshot of stack block before annotation](https://github.com/droe/binja-blocks/blob/0.3.4/.github/img/stack_block_before.png?raw=true)

Stack block after annotation:

![Screenshot of stack block after annotation](https://github.com/droe/binja-blocks/blob/0.3.4/.github/img/stack_block_after.png?raw=true)

Invoke function before annotation:

![Screenshot of invoke function before annotation](https://github.com/droe/binja-blocks/blob/0.3.4/.github/img/invoke_before.png?raw=true)

Invoke function after annotation:

![Screenshot of invoke function after annotation](https://github.com/droe/binja-blocks/blob/0.3.4/.github/img/invoke_after.png?raw=true)

Commands:

-   Annotate all blocks
-   Annotate all global blocks
-   Annotate all stack blocks
-   Annotate global block here
-   Annotate stack block here
-   Remove plugin comment here

Features:

-   Annotate global blocks
-   Annotate stack blocks
-   Annotate block imported variables for extended layout with compact or
    bytecode layout encodings
-   Annotate block descriptors
-   Annotate block invoke function type based on encoded block ObjC type
    signature
-   Annotate block copy and dispose functions
-   Annotate stack byrefs
-   Annotate stack byref fields for non-extended layout
-   Annotate stack byref fields for extended layout with compact or bytecode
    layout encodings
-   Define per-block named structs to allow for manual fixups
-   Define structs for fully manual annotation: `Block_literal`,
    `Block_descriptor_1`, `Block_descriptor_2`, `Block_descriptor_3`,
    `Block_byref_1`, `Block_byref_2`, `Block_byref_3`.
-   Relevant enums for completeness
-   Support for 64-bit architectures

Planned improvements, PRs welcome:

-   Automatically create structs for which internal type info is available,
    unless they can be pulled from some type archive
-   Allow re-annotating already annotated blocks, e.g. after partial failure or
    manual changes
-   Plugin command to annotate byrefs manually more conveniently than
    annotating the type
-   Annotate byref block keep and destroy functions

Less likely to get implemented, but PRs welcome:

-   Support for 32-bit architectures
-   Support older block layout from before the introduction of block descriptors
-   Discover and annotate block stack unwind handlers
-   Find and annotate byrefs passed as arguments

## License

This plugin is released under an [MIT license](./license).
