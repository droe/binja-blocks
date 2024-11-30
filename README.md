# Apple Blocks Plugin
Author: Daniel Roethlisberger

Annotation of Apple [libclosure](https://github.com/apple-oss-distributions/libclosure) [blocks](https://clang.llvm.org/docs/BlockLanguageSpec.html).

## Description

Type annotation of stack and global blocks, block descriptors, variables closed
over and related function signatures in [Binary Ninja](https://binary.ninja/).
Blocks are an implementation of closures often found in C, C++, ObjC and ObjC++
code for Apple platforms.  Blocks are not the same as C++ lambdas.

This plugin should be considered experimental and will almost certainly benefit
from further improvements.  PRs and feedback welcome.

Commands:

-   Annotate all blocks
-   Annotate all global blocks
-   Annotate all stack blocks
-   Global block here
-   Stack block here

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

-   Find stack writes beyond end of struct but within size, between insn that
    set up structure and first reference of structure, and pick up as
    non-pointer imported fields
-   Automatically create structs for which internal type info is available,
    unless they can be pulled from some type archive
-   Allow re-annotating already annotated blocks, e.g. after partial failure or
    manual changes
-   Annotate block imported variables for non-extended layout
-   Plugin command to annotate byrefs manually more conveniently than
    annotating the type

Less likely to get implemented, but PRs welcome:

-   Support for 32-bit architectures
-   Annotate byref block keep and destroy functions
-   Discover and annotate block stack unwind handlers
-   Find and annotate byrefs passed as arguments

## License

This plugin is released under an [MIT license](./license).
