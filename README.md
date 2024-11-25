# Apple Blocks Plugin
Author: Daniel Roethlisberger

Annotation of Apple [libclosure](https://github.com/apple-oss-distributions/libclosure) [blocks](https://clang.llvm.org/docs/BlockLanguageSpec.html).

## Description

Automate annotation of stack and global blocks, block descriptors, variables
closed over and function signatures.  Blocks are an implementation of closures
often found in C, C++, ObjC and ObjC++ code for Apple platforms.

This plugin should be considered experimental and may require fixes, PRs
welcome.

Commands:

-   Annotate all blocks
-   Annotate all global blocks
-   Annotate all stack blocks
-   Global block here
-   Stack block here

Features:

-   Annotate global blocks
-   Annotate stack blocks
-   Annotate block imported variables for extended layout with compact layout encoding
-   Annotate block descriptors
-   Annotate block invoke function type based on encoded block signature
-   Annotate block copy and dispose functions
-   Annotate stack byrefs
-   Annotate stack byref fields for non-extended layout
-   Annotate stack byref fields for extended layout with compact layout encoding
-   Define per-block named structs to allow for manual fixups
-   Define structs for manual annotation: `Block_literal`, `Block_descriptor_1`, `Block_descriptor_2`, `Block_descriptor_3`, `Block_byref_1`, `Block_byref_2`, `Block_byref_3`.
-   Relevant enums for completeness
-   Support for 64-bit architectures

Planned improvements, PRs welcome:

-   Propagate byref types to block literal types
-   Annotate block imported variables for extended layout with bytecode
-   Annotate block imported variables for non-extended layout
-   Annotate stack byref fields for extended layout with bytecode
-   Plugin command to annotate byrefs manually more conveniently than annotating the type

Less likely to get implemented, but PRs welcome:

-   Support for 32-bit architectures
-   Discover and annotate block stack unwind handlers
-   Find and annotate byrefs passed as arguments
-   Annotate byref block keep and dispose functions

## License

This plugin is released under an [MIT license](./license).
