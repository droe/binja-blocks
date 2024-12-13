# Apple Blocks Plugin
Author: Daniel Roethlisberger

Annotation of Apple [libclosure](https://github.com/apple-oss-distributions/libclosure) [blocks](https://clang.llvm.org/docs/BlockLanguageSpec.html).

## Description

Type annotation of stack and global blocks, block descriptors, variables closed
over and related function signatures in [Binary Ninja](https://binary.ninja/).
Blocks are an implementation of closures often found in C, C++, ObjC and ObjC++
code for Apple platforms.  Blocks are not the same as C++ lambdas.

Stack block before annotation:

![Screenshot of stack block before annotation](https://github.com/droe/binja-blocks/blob/0.3.6/.github/img/stack_block_before.png?raw=true)

Stack block after annotation:

![Screenshot of stack block after annotation](https://github.com/droe/binja-blocks/blob/0.3.6/.github/img/stack_block_after.png?raw=true)

Invoke function before annotation:

![Screenshot of invoke function before annotation](https://github.com/droe/binja-blocks/blob/0.3.6/.github/img/invoke_before.png?raw=true)

Invoke function after annotation:

![Screenshot of invoke function after annotation](https://github.com/droe/binja-blocks/blob/0.3.6/.github/img/invoke_after.png?raw=true)

Commands:

-   Annotate all blocks
-   Annotate all global blocks
-   Annotate all stack blocks
-   Annotate global block here
-   Annotate stack block here
-   Remove plugin comment here

Features:

-   Find and annotate global and stack blocks
-   Annotate block imported variables for extended layout with compact or
    bytecode layout encodings
-   Annotate block invoke function type based on encoded block ObjC type
    signature
-   Annotate block descriptors and copy/dispose functions
-   Annotate stack byrefs (`__block` variables) for non-extended layout as
    well as extended layout with compact or bytecode layout encodings
-   Define per-block named structs to allow for manual fixups
-   Define structs for fully manual annotation: `Block_literal`,
    `Block_descriptor_1`, `Block_descriptor_2`, `Block_descriptor_3`,
    `Block_byref_1`, `Block_byref_2`, `Block_byref_3`.

Known limitations:

-   No support for "small descriptors"
-   No support for 32-bit architectures
-   No support for "old GC layout"
-   No support for older block layout from before the introduction of block descriptors
-   Byrefs passed as function arguments are not automatically discovered

## References

Blocks language docs:

-   [Blocks Programming Topics](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Blocks/), Apple Documentation Archive
-   [LLVM Block Language Spec](https://clang.llvm.org/docs/BlockLanguageSpec.html)

Blocks implementation details:

-   [libclosure](https://github.com/apple-oss-distributions/libclosure), source code and two spec documents
-   [LLVM Block ABI](https://clang.llvm.org/docs/Block-ABI-Apple.html)

Objective-C Type Encodings:

-   [Type Encodings](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html), Objective-C Runtime Programming Guide, Apple Documentation Archive
-   [LLVM code emitting type encodings](https://github.com/llvm-mirror/clang/blob/master/lib/AST/ASTContext.cpp)

## License

This plugin is released under an [MIT license](./license).
