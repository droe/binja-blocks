# Copyright (c) 2024 Daniel Roethlisberger
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import binaryninja as binja

import sys
import traceback

from . import shinobi
from . import objctypes


# Had to disable is_valid due to spurious exceptions in Binary Ninja Core.
# https://github.com/Vector35/binaryninja-api/issues/6254
# https://github.com/droe/binja-blocks/issues/5
is_valid = None
#def is_valid(bv, arg=None):
#    return bv.arch.name in (
#        'aarch64',
#        'x86_64',
#        #'armv7',
#        #'x86',
#    )


_TYPE_ID_SOURCE = "binja-blocks"
_LOGGER_NAME = "Apple Blocks"


_OBJC_TYPE_SOURCE = """
struct objc_class {
};

typedef struct objc_class* Class;

struct objc_object {
    Class isa;
};

typedef struct objc_object* id;
"""

_LIBCLOSURE_TYPE_SOURCE = """
enum Block_flags : uint32_t {
    BLOCK_DEALLOCATING                  = 0x0001U,      // runtime
//  BLOCK_REFCOUNT_MASK                 = 0xfffeU,      // runtime

    // in-descriptor flags only
//  BLOCK_GENERIC_HELPER_NONE           = 0U << 14,     // compiler
//  BLOCK_GENERIC_HELPER_FROM_LAYOUT    = 1U << 14,     // compiler
//  BLOCK_GENERIC_HELPER_INLINE         = 2U << 14,     // compiler
//  BLOCK_GENERIC_HELPER_OUTOFLINE      = 3U << 14,     // compiler
//  BLOCK_GENERIC_HELPER_MASK           = 3U << 14,     // compiler
    BLOCK_GENERIC_HELPER_BIT0           = 1U << 14,     // compiler
    BLOCK_GENERIC_HELPER_BIT1           = 1U << 15,     // compiler

    BLOCK_INLINE_LAYOUT_STRING          = 1U << 21,     // compiler
    BLOCK_SMALL_DESCRIPTOR              = 1U << 22,     // compiler
    BLOCK_IS_NOESCAPE                   = 1U << 23,     // compiler
    BLOCK_NEEDS_FREE                    = 1U << 24,     // runtime
    BLOCK_HAS_COPY_DISPOSE              = 1U << 25,     // compiler
    BLOCK_HAS_CTOR                      = 1U << 26,     // compiler
    BLOCK_IS_GC                         = 1U << 27,     // runtime
    BLOCK_IS_GLOBAL                     = 1U << 28,     // compiler
    BLOCK_USE_STRET                     = 1U << 29,     // compiler
    BLOCK_HAS_SIGNATURE                 = 1U << 30,     // compiler
    BLOCK_HAS_EXTENDED_LAYOUT           = 1U << 31,     // compiler
};

enum Block_byref_flags : uint32_t {
    BLOCK_BYREF_DEALLOCATING            = 0x0001U,      // runtime
//  BLOCK_BYREF_REFCOUNT_MASK           = 0xfffeU,      // runtime
    BLOCK_BYREF_NEEDS_FREE              = 1U << 24,     // runtime
    BLOCK_BYREF_HAS_COPY_DISPOSE        = 1U << 25,     // compiler
    BLOCK_BYREF_IS_GC                   = 1U << 27,     // runtime
//  BLOCK_BYREF_LAYOUT_MASK             = 7U << 28,     // compiler
//  BLOCK_BYREF_LAYOUT_EXTENDED         = 1U << 28,     // compiler
//  BLOCK_BYREF_LAYOUT_NON_OBJECT       = 2U << 28,     // compiler
//  BLOCK_BYREF_LAYOUT_STRONG           = 3U << 28,     // compiler
//  BLOCK_BYREF_LAYOUT_WEAK             = 4U << 28,     // compiler
//  BLOCK_BYREF_LAYOUT_UNRETAINED       = 5U << 28,     // compiler
    BLOCK_BYREF_LAYOUT_BIT0             = 1U << 28,     // compiler
    BLOCK_BYREF_LAYOUT_BIT1             = 1U << 29,     // compiler
    BLOCK_BYREF_LAYOUT_BIT2             = 1U << 30,     // compiler
};

typedef void(*BlockCopyFunction)(void *, const void *);
typedef void(*BlockDisposeFunction)(const void *);
typedef void(*BlockInvokeFunction)(void *, ...);

struct Block_byref_1 {
    Class isa;
    struct Block_byref_1 *forwarding;
    volatile enum Block_byref_flags flags;
    uint32_t size;
};

typedef void(*BlockByrefKeepFunction)(struct Block_byref*, struct Block_byref*);
typedef void(*BlockByrefDestroyFunction)(struct Block_byref *);

struct Block_byref_2 {
    BlockByrefKeepFunction keep;
    BlockByrefDestroyFunction destroy;
};

struct Block_byref_3 {
    const char *layout;
};

struct Block_descriptor_1 {
    enum Block_flags flags;
    uint32_t reserved;
    uint64_t size;
};

struct Block_descriptor_2 {
    BlockCopyFunction copy;
    BlockDisposeFunction dispose;
};

struct Block_descriptor_3 {
    const char *signature;
    const uint8_t *layout;
};

struct Block_literal {
    Class isa;
    volatile enum Block_flags flags;
    uint32_t reserved;
    BlockInvokeFunction invoke;
    struct Block_descriptor_1 *descriptor;
};
"""

BLOCK_HAS_EXTENDED_LAYOUT           = 0x80000000
BLOCK_HAS_SIGNATURE                 = 0x40000000
BLOCK_IS_GLOBAL                     = 0x10000000
BLOCK_HAS_COPY_DISPOSE              = 0x02000000
BLOCK_SMALL_DESCRIPTOR              = 0x00400000

BLOCK_GENERIC_HELPER_MASK           = 0x0000C000
BLOCK_GENERIC_HELPER_NONE           = 0x00000000
BLOCK_GENERIC_HELPER_FROM_LAYOUT    = 0x00004000
BLOCK_GENERIC_HELPER_INLINE         = 0x00008000
BLOCK_GENERIC_HELPER_OUTOFLINE      = 0x0000C000

BLOCK_BYREF_HAS_COPY_DISPOSE        = 0x02000000
BLOCK_BYREF_LAYOUT_MASK             = 0x70000000
BLOCK_BYREF_LAYOUT_EXTENDED         = 0x10000000
BLOCK_BYREF_LAYOUT_NON_OBJECT       = 0x20000000
BLOCK_BYREF_LAYOUT_STRONG           = 0x30000000
BLOCK_BYREF_LAYOUT_WEAK             = 0x40000000
BLOCK_BYREF_LAYOUT_UNRETAINED       = 0x50000000

BLOCK_LAYOUT_ESCAPE                 = 0x0
BLOCK_LAYOUT_NON_OBJECT_BYTES       = 0x1
BLOCK_LAYOUT_NON_OBJECT_WORDS       = 0x2
BLOCK_LAYOUT_STRONG                 = 0x3
BLOCK_LAYOUT_BYREF                  = 0x4
BLOCK_LAYOUT_WEAK                   = 0x5
BLOCK_LAYOUT_UNRETAINED             = 0x6

BCK_DONE                            = 0x0
BCK_NON_OBJECT_BYTES                = 0x1
BCK_NON_OBJECT_WORDS                = 0x2
BCK_STRONG                          = 0x3
BCK_BLOCK                           = 0x4
BCK_BYREF                           = 0x5
BCK_WEAK                            = 0x6

def _get_custom_type_internal(bv, name, typestr, source, dependency=None):
    assert (name is None) != (typestr is None)

    def make_type():
        if name is not None:
            return bv.get_type_by_name(name)
        else:
            try:
                return bv.parse_type_string(typestr)[0]
            except SyntaxError:
                return None

    type_ = make_type()
    if type_ is not None:
        return type_

    if dependency is not None:
        dependency()

    types = bv.parse_types_from_string(source)
    bv.define_types([(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, k), k, v) for k, v in types.types.items()], None)

    type_ = make_type()
    assert type_ is not None
    return type_


def _get_objc_type(bv, name):
    """
    Get a type object for an Objective-C type that we ship stand-in
    types for, by name.  For a struct or an enum, this returns an
    anonymous struct or enum, not a reference to the named type.
    """
    return _get_custom_type_internal(bv, name, None, _OBJC_TYPE_SOURCE)


def _parse_objc_type(bv, typestr):
    """
    Parse a type string containing Objective-C types that we ship
    standin types for.  When passed "struct Foo" or "enum Foo",
    returns a reference to a named type, suitable for annotating
    field members.
    """
    return _get_custom_type_internal(bv, None, typestr, _OBJC_TYPE_SOURCE)


def _get_libclosure_type(bv, name):
    """
    Get a type object for a libclosure type that we ship with
    the plugin, by name.  For a struct or an enum, this returns an
    anonymous struct or enum, not a reference to the named type.
    """
    return _get_custom_type_internal(bv, name, None, _LIBCLOSURE_TYPE_SOURCE,
                                     lambda: _get_objc_type(bv, "Class"))


def _parse_libclosure_type(bv, typestr):
    """
    Parse a type string containing libclosure types that we ship with
    the plugin.  When passed "struct Foo" or "enum Foo", returns a
    reference to a named type, suitable for annotating field members.
    """
    return _get_custom_type_internal(bv, None, typestr, _LIBCLOSURE_TYPE_SOURCE,
                                     lambda: _get_objc_type(bv, "Class"))


def _define_ns_concrete_block_imports(bv):
    """
    For some reason, Binary Ninja does not reliably define all external symbols.
    Make sure __NSConcreteGlobalBlock and __NSConcreteStackBlock are defined
    appropriately.
    """
    objc_class_type = _parse_objc_type(bv, "Class")
    for sym_name in ("__NSConcreteGlobalBlock", "__NSConcreteStackBlock"):
        for sym_type in (binja.SymbolType.ExternalSymbol, binja.SymbolType.DataSymbol):
            sym = bv.get_symbol_of_type(sym_name, sym_type)
            if sym is None or sym.address == 0:
                continue
            bv.make_data_var(sym.address, objc_class_type)
            break


def _blocks_plugin_logger(self):
    """
    Get this plugin's logger for the view.
    Create the logger if it does not exist yet.
    Monkey-patching this in to avoid having to pass around
    a separate logger with the same lifetime as the view.
    """
    logger = getattr(self, '_blocks_plugin_logger', None)
    if logger is None:
        logger = self.create_logger(_LOGGER_NAME)
        self._blocks_plugin_logger = logger
    return logger
binja.BinaryView.blocks_plugin_logger = property(_blocks_plugin_logger)


def append_layout_fields(bv, struct,
                         generic_helper_type, generic_helper_info, generic_helper_info_bytecode,
                         block_has_extended_layout, layout, layout_bytecode,
                         byref_indexes=None):
    """
    Append fields for imported variables to struct, which is either
    a block literal struct or a byref struct.

    If generic helper info is available, derive the field layout
    from generic_helper_info and generic_helper_info_bytecode.
    Otherwise, if layout is available, derive the field layout
    from layout and layout_bytecode.
    If neither is available, do not append any fields to struct.

    If byref_indexes is given, the struct member index of all byref
    pointers is appended to byref_indexes.
    """
    id_type = _parse_objc_type(bv, "id")
    u64_type = bv.parse_type_string("uint64_t")[0]

    if generic_helper_type == BLOCK_GENERIC_HELPER_INLINE:
        assert generic_helper_info_bytecode is None
        assert generic_helper_info is not None
        assert isinstance(generic_helper_info, int)
        assert (0xFFFFFFFFF00000FF & generic_helper_info) == 0
        n_strong_ptrs = (generic_helper_info >> 8) & 0xf
        n_block_ptrs = (generic_helper_info >> 12) & 0xf
        n_byref_ptrs = (generic_helper_info >> 16) & 0xf
        n_weak_ptrs = (generic_helper_info >> 20) & 0xf
        for _ in range(n_strong_ptrs):
            struct.append_with_offset_suffix(id_type, "strong_ptr_")
        for _ in range(n_block_ptrs):
            struct.append_with_offset_suffix(id_type, "block_ptr_")
        for _ in range(n_byref_ptrs):
            if byref_indexes is not None:
                byref_indexes.append(len(struct.members))
            struct.append_with_offset_suffix(id_type, "byref_ptr_")
        for _ in range(n_weak_ptrs):
            struct.append_with_offset_suffix(id_type, "weak_ptr_")
        return

    if generic_helper_type == BLOCK_GENERIC_HELPER_OUTOFLINE:
        assert generic_helper_info_bytecode is not None
        for op in generic_helper_info_bytecode[1:]:
            opcode = (op & 0xf0) >> 4
            oparg = (op & 0x0f)
            if opcode == BCK_DONE:
                break
            elif opcode == BCK_NON_OBJECT_BYTES:
                struct.append_with_offset_suffix(bv.parse_type_string(f"uint8_t [{oparg}]")[0], "non_object_")
            elif opcode == BCK_NON_OBJECT_WORDS:
                for _ in range(oparg):
                    struct.append_with_offset_suffix(u64_type, "non_object_")
            elif opcode == BCK_STRONG:
                for _ in range(oparg):
                    struct.append_with_offset_suffix(id_type, "strong_ptr_")
            elif opcode == BCK_BLOCK:
                for _ in range(oparg):
                    struct.append_with_offset_suffix(id_type, "block_ptr_")
            elif opcode == BCK_BYREF:
                for _ in range(oparg):
                    if byref_indexes is not None:
                        byref_indexes.append(len(struct.members))
                    struct.append_with_offset_suffix(id_type, "byref_ptr_")
            elif opcode == BCK_WEAK:
                for _ in range(oparg):
                    struct.append_with_offset_suffix(id_type, "weak_ptr_")
            else:
                bv.blocks_plugin_logger.log_warn(f"Unknown generic helper op {op:#04x}")
                break
        return

    if block_has_extended_layout and layout != 0:
        if layout < 0x1000:
            # inline layout encoding
            assert layout_bytecode is None
            n_strong_ptrs = (layout >> 8) & 0xf
            n_byref_ptrs = (layout >> 4) & 0xf
            n_weak_ptrs = layout & 0xf
            for _ in range(n_strong_ptrs):
                struct.append_with_offset_suffix(id_type, "strong_ptr_")
            for _ in range(n_byref_ptrs):
                if byref_indexes is not None:
                    byref_indexes.append(len(struct.members))
                struct.append_with_offset_suffix(id_type, "byref_ptr_")
            for _ in range(n_weak_ptrs):
                struct.append_with_offset_suffix(id_type, "weak_ptr_")
        else:
            # out-of-line layout string
            assert layout_bytecode is not None
            for op in layout_bytecode:
                opcode = (op & 0xf0) >> 4
                oparg = (op & 0x0f)
                if opcode == BLOCK_LAYOUT_ESCAPE:
                    break
                elif opcode == BLOCK_LAYOUT_NON_OBJECT_BYTES:
                    struct.append_with_offset_suffix(bv.parse_type_string(f"uint8_t [{oparg}]")[0], "non_object_")
                elif opcode == BLOCK_LAYOUT_NON_OBJECT_WORDS:
                    for _ in range(oparg):
                        struct.append_with_offset_suffix(u64_type, "non_object_")
                elif opcode == BLOCK_LAYOUT_STRONG:
                    for _ in range(oparg):
                        struct.append_with_offset_suffix(id_type, "strong_ptr_")
                elif opcode == BLOCK_LAYOUT_BYREF:
                    for _ in range(oparg):
                        if byref_indexes is not None:
                            byref_indexes.append(len(struct.members))
                        struct.append_with_offset_suffix(id_type, "byref_ptr_")
                elif opcode == BLOCK_LAYOUT_WEAK:
                    for _ in range(oparg):
                        struct.append_with_offset_suffix(id_type, "weak_ptr_")
                elif opcode == BLOCK_LAYOUT_UNRETAINED:
                    for _ in range(oparg):
                        struct.append_with_offset_suffix(id_type, "unretained_ptr_")
                else:
                    bv.blocks_plugin_logger.log_warn(f"Unknown extended layout op {op:#04x}")
                    break


class BlockLiteral:
    class NotABlockLiteralError(Exception):
        pass

    class FailedToFindFieldsError(Exception):
        pass

    @classmethod
    def from_data(cls, bv, bl_data_var, sym_addrs):
        """
        Read block literal from data.
        """
        is_stack_block = False
        br = binja.BinaryReader(bv)
        br.seek(bl_data_var.address)

        isa = br.read64()
        if isa is None:
            raise BlockLiteral.NotABlockLiteralError("isa does not exist")
        if isa not in sym_addrs:
            raise BlockLiteral.NotABlockLiteralError("isa is not __NSConcreteGlobalBlock")

        flags = br.read32()
        if flags is None:
            raise BlockLiteral.NotABlockLiteralError("flags does not exist")
        if (flags & BLOCK_IS_GLOBAL) == 0:
            raise BlockLiteral.NotABlockLiteralError(f"BLOCK_IS_GLOBAL ({BLOCK_IS_GLOBAL:#010x}) not set in flags")

        reserved = br.read32()
        if reserved is None:
            raise BlockLiteral.NotABlockLiteralError("reserved does not exist")

        invoke = br.read64()
        if invoke is None:
            raise BlockLiteral.NotABlockLiteralError("invoke does not exist")
        if invoke == 0:
            raise BlockLiteral.NotABlockLiteralError("invoke is NULL")

        descriptor = br.read64()
        if descriptor is None:
            raise BlockLiteral.NotABlockLiteralError("descriptor does not exist")
        if descriptor == 0:
            raise BlockLiteral.NotABlockLiteralError("descriptor is NULL")

        return cls(bv, is_stack_block, bl_data_var, isa, flags, reserved, invoke, descriptor)

    @classmethod
    def from_stack(cls, bv, bl_insn, bl_var, sym_addrs):
        is_stack_block = True
        bl_var.type = _parse_libclosure_type(bv, "struct Block_literal")

        bl_insn = bv.reload_hlil_instruction(bl_insn,
                lambda insn: \
                        isinstance(insn, binja.HighLevelILAssign) and \
                        isinstance(insn.dest, binja.HighLevelILStructField) and \
                        isinstance(insn.dest.src, binja.HighLevelILVar) and \
                        str(insn.dest.src.var.type) == 'struct Block_literal')
        stack_var_id = bl_insn.dest.src.var.identifier

        for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(bl_insn.function, stack_var_id):
            if insn.dest.member_index == 0:
                if isinstance(insn.src, (binja.HighLevelILImport,
                                         binja.HighLevelILConstPtr)) and \
                        insn.src.constant in sym_addrs:
                    isa = insn.src.constant
            elif insn.dest.member_index == 1:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    flags = insn.src.constant
            elif insn.dest.member_index == 2:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    reserved = insn.src.constant
                else:
                    reserved = None
            elif insn.dest.member_index == 3:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    invoke = insn.src.constant
            elif insn.dest.member_index == 4:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    descriptor = insn.src.constant
            else:
                # We don't know if the members are assigned in-order,
                # so we cannot rely on having descriptor and hence
                # size available.  As a result, do not attempt to pick
                # up imported variables here.  We'll need another pass
                # for that later.
                pass
            local_vars = locals()
            if all([vn in local_vars for vn in ('isa', 'flags', 'reserved', 'invoke', 'descriptor')]):
                break
        local_vars = locals()
        missing_vars = list(filter(lambda vn: vn not in local_vars, ('isa', 'flags', 'reserved', 'invoke', 'descriptor')))
        if len(missing_vars) > 0:
            raise BlockLiteral.FailedToFindFieldsError(f"{', '.join(missing_vars)}; likely due to complex HLIL")

        if invoke == 0:
            raise BlockLiteral.NotABlockLiteralError("invoke is NULL")
        if descriptor == 0:
            raise BlockLiteral.NotABlockLiteralError("descriptor is NULL")

        return cls(bv, is_stack_block, bl_insn, isa, flags, reserved, invoke, descriptor)

    def __init__(self, bv, is_stack_block, insn_or_data_var, isa, flags, reserved, invoke, descriptor):
        self._bv = bv
        self.is_stack_block = is_stack_block
        if self.is_stack_block:
            self.insn = insn_or_data_var
            self.data_var = None
            self.address = self.insn.address
        else:
            self.insn = None
            self.data_var = insn_or_data_var
            self.address = self.data_var.address
        self.isa = isa
        self.flags = flags
        self.reserved = reserved
        self.invoke = invoke
        self.descriptor = descriptor
        assert self.invoke != 0
        assert self.descriptor != 0
        if self.is_stack_block:
            assert (self.flags & BLOCK_IS_GLOBAL) == 0
        else:
            assert (self.flags & BLOCK_IS_GLOBAL) != 0

    def __str__(self):
        if self.is_stack_block:
            block = f"Stack block"
        else:
            block = f"Global block"
        return f"{block} at {self.address:x} with flags {self.flags:08x} invoke {self.invoke:x} descriptor {self.descriptor:x}"

    def annotate_literal(self, bd):
        """
        Annotate the block literal.
        """
        # Packed because block layout bytecode can lead to misaligned words,
        # which according to comments in LLVM source code seems intentional.
        struct = binja.StructureBuilder.create(packed=True, width=bd.size)
        struct.append(_parse_objc_type(self._bv, "Class"), "isa")
        struct.append(_parse_libclosure_type(self._bv, "enum Block_flags"), "flags")
        struct.append(self._bv.parse_type_string("uint32_t reserved")[0], "reserved")
        struct.append(_get_libclosure_type(self._bv, "BlockInvokeFunction"), "invoke")
        struct.append(binja.Type.pointer(self._bv.arch, _parse_libclosure_type(self._bv, "struct Block_descriptor_1")), "descriptor") # placeholder
        self.byref_indexes = []
        if bd.imported_variables_size > 0 and bd.block_has_signature and bd.layout is not None:
            append_layout_fields(self._bv, struct,
                                 bd.generic_helper_type, bd.generic_helper_info, bd.generic_helper_info_bytecode,
                                 bd.block_has_extended_layout, bd.layout, bd.layout_bytecode,
                                 self.byref_indexes)
        self.struct_builder = struct
        self.struct_name = f"Block_literal_{self.address:x}"
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.struct_name), self.struct_name, self.struct_builder)
        self.struct_type_name = f"struct {self.struct_name}"
        self.struct_type = self._bv.parse_type_string(self.struct_type_name)[0]
        assert self.struct_type is not None
        if self.is_stack_block:
            assert isinstance(self.insn, binja.HighLevelILAssign)
            assert isinstance(self.insn.dest, binja.HighLevelILStructField)
            assert isinstance(self.insn.dest.src, binja.HighLevelILVar)
            stack_var = self.insn.dest.src.var
            stack_var_type_name = str(stack_var.type)
            if stack_var_type_name.startswith("struct Block_literal_") and stack_var_type_name != self.struct_type_name:
                # Stack var has already been annotated for initialization code
                # at a different address, likely because multiple branches in
                # the function place a block at the same stack address.
                # Unfortunately, this seems to be a hypothetical situation
                # right now, as Binja does not seem to handle different use of
                # the same stack area by different branches gracefully.
                self._bv.blocks_plugin_logger.log_warn(f"Block literal at {self.address:x}: Stack var {stack_var.name} already annotated with type {stack_var_type_name}; defined {self.struct_type_name} but did not clobber var type, splitting the stack var might help")
                return

            if not stack_var.name.startswith("stack_block_"):
                stack_var.name = f"stack_block_{stack_var.name}"
            stack_var.type = self.struct_type_name
            self.insn = self._bv.reload_hlil_instruction(self.insn,
                    lambda insn: \
                            isinstance(insn, binja.HighLevelILAssign) and \
                            isinstance(insn.dest, binja.HighLevelILStructField) and \
                            isinstance(insn.dest.src, binja.HighLevelILVar) and \
                            str(insn.dest.src.var.type).startswith('struct Block_literal_'))
        else:
            self.data_var.name = f"global_block_{self.address:x}"
            self.data_var.type = self.struct_type_name

    def _type_for_ctype(self, ctype):
        if ctype.endswith("!"):
            fallback = 'id'
            ctype = ctype.replace("!", "*")
        elif ctype.endswith("*"):
            fallback = 'void *'
        else:
            fallback = 'void'
        try:
            return self._bv.parse_type_string(ctype)[0]
        except SyntaxError:
            # XXX if struct or union and we have member type info, create struct or union and retry
            return self._bv.parse_type_string(fallback)[0]

    def annotate_functions(self, bd):
        """
        Annotate the invoke function as well as the copy and dispose functions, if they exist.
        """
        invoke_func = self._bv.get_function_at(self.invoke)
        if invoke_func is not None:
            if bd.signature_raw is not None:
                # This works well for most blocks, but because Binja does
                # not seem to support [Apple's variant of] AArch64 calling
                # conventions properly when things are passed in v registers
                # or on the stack, signatures are sometimes wrong.  I find
                # it useful to have them, even if they are sometimes wrong.
                # The types assigned here should be correct, assuming no
                # fallbacks to void were required (those may cause size to
                # be lost, which for structs by value determines if they
                # get passed in multiple registers or on the stack).
                try:
                    ctypes = objctypes.ObjCEncodedTypes(bd.signature_raw).ctypes
                    assert len(ctypes) > 0
                    types = list(map(self._type_for_ctype, ctypes))
                    types[1] = binja.Type.pointer(self._bv.arch, self.struct_type)
                    func_type = binja.Type.function(types[0], types[1:])
                except NotImplementedError as e:
                    self._bv.blocks_plugin_logger.log_error(f"Failed to parse ObjC type encoding {bd.signature_raw!r}: {type(e).__name__}: {e}")
                    func_type = None
            else:
                # No signature string.
                func_type = None

            if func_type is None and len(invoke_func.parameter_vars) == 0:
                # If Binja did not pick up on any parameters, fall back to a vararg
                # signature.  We're not going to clobber any parameter types.
                func_type = binja.Type.function(binja.Type.void(), [binja.Type.pointer(self._bv.arch, self.struct_type)], variable_arguments=True)

            if func_type is None:
                # Finally fall back to surgically setting return and first argument
                # types, leaving the other parameters undisturbed.
                invoke_func.return_type = binja.Type.void()
                invoke_func.parameter_vars[0].set_name_and_type_async("block", binja.Type.pointer(self._bv.arch, self.struct_type))
                self._bv.update_analysis_and_wait()

            else:
                # Set function type.

                # As of Binja 4.2, the setter for Function.type does not
                # update_analysis_and_wait(), unlike the Variable.name and
                # Variable.type setters that do.  Also, the setter for
                # Variable.name is not atomic; it will first copy the current
                # type, then proceed to set both name and type on the variable.
                # As a result, we need to update_analysis_and_wait() manually
                # to avoid an easy-to-repro race condition where a subsequent
                # assignment to Variable.name while the Function.type
                # assignment is still in flight may clobber the type for the
                # first parameter with the type it had before assigning the
                # function type.
                invoke_func.type = func_type
                self._bv.update_analysis_and_wait()

                if len(invoke_func.parameter_vars) >= 1:
                    invoke_func.parameter_vars[0].name = "block"

                # propagate invoke function signature to invoke pointer on block literal
                invoke_pointer_index = self.struct_builder.index_by_name("invoke")
                self.struct_builder.replace(invoke_pointer_index,
                                            binja.Type.pointer(self._bv.arch, func_type), "invoke")
                self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.struct_name),
                                     self.struct_name, self.struct_builder)
                self.struct_type = self._bv.parse_type_string(self.struct_type_name)[0]

            if invoke_func.name == f"sub_{invoke_func.start:x}":
                invoke_func.name = f"sub_{invoke_func.start:x}_block_invoke"

        # XXX move remainder to BlockDescriptor when switching to one block literal struct type per descriptor

        if bd.block_has_copy_dispose:
            # Interleave annotation of the two functions in order to minimize
            # the number of expensive calls to update_analysis_and_wait().
            copy_func = self._bv.get_function_at(bd.copy)
            dispose_func = self._bv.get_function_at(bd.dispose)
            if copy_func is not None or dispose_func is not None:
                if copy_func is not None:
                    copy_func.type = binja.Type.function(binja.Type.void(),
                                                         [binja.Type.pointer(self._bv.arch, self.struct_type),
                                                          binja.Type.pointer(self._bv.arch, self.struct_type)])
                if dispose_func is not None:
                    dispose_func.type = binja.Type.function(binja.Type.void(),
                                                            [binja.Type.pointer(self._bv.arch, self.struct_type)])
                self._bv.update_analysis_and_wait()

                if copy_func is not None:
                    if len(copy_func.parameter_vars) >= 2:
                        copy_func.parameter_vars[0].set_name_async("dst")
                        copy_func.parameter_vars[1].set_name_async("src")
                if dispose_func is not None:
                    if len(dispose_func.parameter_vars) >= 1:
                        dispose_func.parameter_vars[0].set_name_async("dst")
                self._bv.update_analysis_and_wait()

                if copy_func is not None:
                    if copy_func.name == f"sub_{copy_func.start:x}":
                        copy_func.name = f"sub_{copy_func.start:x}_block_copy"

                if dispose_func is not None:
                    if dispose_func.name == f"sub_{dispose_func.start:x}":
                        dispose_func.name = f"sub_{dispose_func.start:x}_block_dispose"


class BlockDescriptor:
    class NotABlockDescriptorError(Exception):
        pass

    def __init__(self, bv, descriptor_address, block_flags):
        """
        Read block descriptor from data.
        """
        self._bv = bv
        self.address = descriptor_address
        self.block_flags = block_flags

        if self.block_has_small_descriptor:
            raise NotImplementedError("Block has small descriptor, see https://github.com/droe/binja-blocks/issues/19")

        br = binja.BinaryReader(self._bv)
        br.seek(self.address)

        self.reserved = br.read64()
        if self.reserved is None:
            raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: reserved field does not exist")
        # in-descriptor flags
        if self.reserved != 0:
            # u32 in_descriptor_flags
            # u32 reserved
            self.in_descriptor_flags = self.reserved & 0xFFFFFFFF
            assert self.in_descriptor_flags & 0xFFFF0000 == block_flags & 0xFFFF0000 & ~BLOCK_SMALL_DESCRIPTOR
        else:
            # u64 reserved
            self.in_descriptor_flags = None

        self.size = br.read64()
        if self.size is None:
            raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: size field does not exist")
        if self.size < 0x20:
            raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: size too small ({self.size} < 0x20)")

        if self.block_has_copy_dispose:
            self.copy = br.read64()
            if self.copy is None:
                raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: copy field does not exist")
            self.dispose = br.read64()
            if self.dispose is None:
                raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: dispose field does not exist")
        else:
            self.copy = None
            self.dispose = None

        if self.block_has_signature:
            self.signature = br.read64()
            if self.signature is None:
                raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: signature field does not exist")
            if self.signature != 0:
                self.signature_raw = self._bv.get_ascii_string_at(self.signature, 0).raw
            else:
                self.signature_raw = None
            if self.block_has_extended_layout or \
                    (self.generic_helper_type != BLOCK_GENERIC_HELPER_NONE) or \
                    (not self.block_has_copy_dispose) or \
                    self.block_is_global:
                # Cases handled by reading and marking up a layout field:
                # a) Descriptor with extended layout.
                # b) Descriptor with generic helper type on in-descriptor flags that implies
                #    presence of layout field (generic helper from layout, inline, out-of-line).
                # c) Descriptor without custom copy/dispose handlers.
                # d) Old descriptor format without extended layout, e.g. "old GC layout",
                #    unsure of semantics, and unsure if relevant for 64-bit archs.
                # e) ABI.2010.3.16 as per https://clang.llvm.org/docs/Block-ABI-Apple.html,
                #    i.e. signature field w/o layout field following, extended layout bit unset;
                #    unsure if this ever existed outside of spec documents.
                #    We'd want to handle this case differently if we had a way to recognise it.
                self.layout = br.read64()
                if self.layout is None:
                    raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: layout field does not exist")
                if self.layout >= 0x1000:
                    # out-of-line layout string
                    self.layout_bytecode = self._bv.get_raw_string_at(self.layout)
                    if self.layout_bytecode is None:
                        raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: out-of-line layout string does not exist")
                else:
                    # inline layout encoding
                    self.layout_bytecode = None
            else:
                # Cases handled by not reading and not marking up a layout field:
                # f) Stack blocks without extended layout, without generic helper info,
                #    with custom copy/dispose handlers.  These seem to sometimes get
                #    emitted without a layout field.
                self.layout = None
                self.layout_bytecode = None

        if self.generic_helper_type in (BLOCK_GENERIC_HELPER_INLINE,
                                        BLOCK_GENERIC_HELPER_OUTOFLINE):
            br.seek(self.address - self._bv.arch.address_size)
            assert self._bv.arch.address_size == 8
            self.generic_helper_info = br.read64()
            if self.generic_helper_info is None:
                raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: generic_helper_info field does not exist")
            if self.generic_helper_type == BLOCK_GENERIC_HELPER_OUTOFLINE:
                assert self.generic_helper_info != 0
                # min_len=1 to include the reserved byte in bytecode even if it's 0.
                self.generic_helper_info_bytecode = self._bv.get_raw_string_at(self.generic_helper_info, min_len=1)
                if self.generic_helper_info_bytecode is None:
                    raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: out-of-line generic helper info string does not exist")
            else:
                self.generic_helper_info_bytecode = None
        else:
            self.generic_helper_info = None
            self.generic_helper_info_bytecode = None

    @property
    def imported_variables_size(self):
        return self.size - 0x20

    @property
    def block_has_copy_dispose(self):
        return (self.block_flags & BLOCK_HAS_COPY_DISPOSE) != 0

    @property
    def block_has_signature(self):
        return (self.block_flags & BLOCK_HAS_SIGNATURE) != 0

    @property
    def block_has_extended_layout(self):
        return (self.block_flags & BLOCK_HAS_EXTENDED_LAYOUT) != 0

    @property
    def block_is_global(self):
        return (self.block_flags & BLOCK_IS_GLOBAL) != 0

    @property
    def block_has_small_descriptor(self):
        return (self.block_flags & BLOCK_SMALL_DESCRIPTOR) != 0

    @property
    def generic_helper_type(self):
        if self.in_descriptor_flags is None:
            return BLOCK_GENERIC_HELPER_NONE
        return (self.in_descriptor_flags & BLOCK_GENERIC_HELPER_MASK)

    def __str__(self):
        if self.in_descriptor_flags:
            flags_s = f" in-descriptor flags {self.in_descriptor_flags:x}"
        else:
            flags_s = ""
        return f"Block descriptor at {self.address:x} size {self.size:#x}{flags_s}"

    def annotate_descriptor(self, bl):
        """
        Annotate block descriptor.
        """
        struct = binja.StructureBuilder.create()
        if self.reserved == 0:
            struct.append(self._bv.parse_type_string("uint64_t reserved")[0], "reserved")
        else:
            assert self.in_descriptor_flags is not None
            struct.append(_parse_libclosure_type(self._bv, "enum Block_flags"), "in_descriptor_flags")
            struct.append(self._bv.parse_type_string("uint32_t reserved")[0], "reserved")
        assert struct.width == 8
        struct.append(self._bv.parse_type_string("uint64_t size")[0], "size")
        if self.block_has_copy_dispose:
            struct.append(_get_libclosure_type(self._bv, "BlockCopyFunction"), "copy")
            struct.append(_get_libclosure_type(self._bv, "BlockDisposeFunction"), "dispose")
        if self.block_has_signature:
            struct.append(self._bv.parse_type_string("char const *signature")[0], "signature")
            if self.layout is not None:
                if self.layout < 0x1000:
                    # inline layout encoding
                    struct.append(self._bv.parse_type_string("uint64_t layout")[0], "layout")
                else:
                    # out-of-line layout string
                    struct.append(self._bv.parse_type_string("uint8_t const *layout")[0], "layout")
            else:
                # Skip the layout field, see ctor for rationale.
                pass
        self.struct_builder = struct
        self.struct_name = f"Block_descriptor_{self.address:x}"
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.struct_name), self.struct_name, self.struct_builder)
        self.struct_type_name = f"struct {self.struct_name}"
        self.struct_type = self._bv.parse_type_string(self.struct_type_name)[0]
        assert self.struct_type is not None
        self._bv.make_data_var(self.address,
                               self.struct_type,
                               f"block_descriptor_{self.address:x}")

        # propagate struct type to descriptor pointer on block literal
        pointer_index = bl.struct_builder.index_by_name("descriptor")
        bl.struct_builder.replace(pointer_index, binja.Type.pointer(self._bv.arch, self.struct_type), "descriptor")
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, bl.struct_name), bl.struct_name, bl.struct_builder)
        bl.struct_type = self._bv.parse_type_string(bl.struct_type_name)[0]

        # annotate generic helper info
        if self.generic_helper_type in (BLOCK_GENERIC_HELPER_INLINE,
                                        BLOCK_GENERIC_HELPER_OUTOFLINE):
            if self.generic_helper_type == BLOCK_GENERIC_HELPER_INLINE:
                generic_helper_info_type = self._bv.parse_type_string("uint64_t")[0]
            else:
                generic_helper_info_type = self._bv.parse_type_string("uint8_t const *")[0]
            self._bv.make_data_var(self.address - self._bv.arch.address_size,
                                   generic_helper_info_type,
                                   f"block_descriptor_{self.address:x}_generic_helper_info")

    def annotate_layout_bytecode(self):
        """
        Annotate the out-of-line layout string, if one exists.
        """
        if self.block_has_signature and self.block_has_extended_layout and self.layout >= 0x1000:
            n = len(self.layout_bytecode)
            self._bv.make_data_var(self.layout,
                                   self._bv.parse_type_string(f"uint8_t [{n}]")[0],
                                   f"block_layout_{self.layout:x}")

    def annotate_generic_helper_info_bytecode(self):
        """
        Annotate the out-of-line generic helper info string, if one exists.
        """
        if self.generic_helper_type == BLOCK_GENERIC_HELPER_OUTOFLINE:
            n = len(self.generic_helper_info_bytecode)
            self._bv.make_data_var(self.generic_helper_info,
                                   self._bv.parse_type_string(f"uint8_t [{n}]")[0],
                                   f"block_generic_helper_info_{self.generic_helper_info:x}")


def annotate_global_block_literal(bv, block_literal_addr, sym_addrs=None):
    where = f"Global block {block_literal_addr:x}"

    bv.blocks_plugin_logger.log_info(f"Annotating {where}")

    if sym_addrs is None:
        sym_addrs = bv.get_symbol_addresses_set("__NSConcreteGlobalBlock")
        if len(sym_addrs) == 0:
            bv.blocks_plugin_logger.log_info("__NSConcreteGlobalBlock not found, target does not appear to contain any global blocks")
            return

    sects = bv.get_sections_at(block_literal_addr)
    if sects is None or len(sects) == 0:
        bv.blocks_plugin_logger.log_warn(f"{where}: Address is not in a section")
        return
    if any([sect.name in ('libsystem_blocks.dylib::__objc_classlist',
                          'libsystem_blocks.dylib::__objc_nlclslist') for sect in sects]):
        bv.blocks_plugin_logger.log_info(f"{where}: Address is in an exempted section that does not contain global blocks")
        return

    block_literal_data_var = bv.get_data_var_at(block_literal_addr)
    if block_literal_data_var is None:
        # We only expect this to happen for manual invocation, not
        # for the automatic sweep, as the sweep requires data
        # references in order to pick up a global block instance.
        class_type = _parse_objc_type(bv, "Class")
        bv.define_user_data_var(block_literal_addr, binja.Type.pointer(bv.arch, class_type))
        block_literal_data_var = bv.get_data_var_at(block_literal_addr)
        assert block_literal_data_var is not None

    data_var_value = block_literal_data_var.value
    if isinstance(data_var_value, dict) and 'isa' in data_var_value:
        data_var_value = data_var_value['isa']
    if not isinstance(data_var_value, int):
        bv.blocks_plugin_logger.log_error(f"{where}: Data var has value {data_var_value} of type {type(data_var_value).__name__}, expected int, fix plugin")
        return
    if data_var_value not in sym_addrs:
        bv.blocks_plugin_logger.log_warn(f"{where}: Data var has value {data_var_value:x} instead of __NSConcreteGlobalBlock")
        return

    try:
        bl = BlockLiteral.from_data(bv, block_literal_data_var, sym_addrs)
        bv.blocks_plugin_logger.log_info(str(bl))
        bd = BlockDescriptor(bv, bl.descriptor, bl.flags)
        bv.blocks_plugin_logger.log_info(str(bd))
        bl.annotate_literal(bd)
        bd.annotate_descriptor(bl)
        bd.annotate_layout_bytecode()
        bd.annotate_generic_helper_info_bytecode()
        bl.annotate_functions(bd)
    except BlockLiteral.NotABlockLiteralError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Not a block literal: {e}")
        return
    except BlockLiteral.FailedToFindFieldsError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Failed to find fields: {e}")
        return
    except BlockDescriptor.NotABlockDescriptorError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Not a block descriptor: {e}")
        return
    except Exception as e:
        bv.blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return


def annotate_stack_block_literal(bv, block_literal_insn, sym_addrs=None):
    where = f"Stack block {block_literal_insn.address:x}"

    bv.blocks_plugin_logger.log_info(f"Annotating {where}")

    if sym_addrs is None:
        sym_addrs = bv.get_symbol_addresses_set("__NSConcreteStackBlock")
        if len(sym_addrs) == 0:
            bv.blocks_plugin_logger.log_info("__NSConcreteStackBlock not found, target does not appear to contain any stack blocks")
            return

    sects = bv.get_sections_at(block_literal_insn.address)
    if sects is None or len(sects) == 0:
        bv.blocks_plugin_logger.log_warn(f"{where}: Address is not in a section")
        return
    if any([sect.name in ('__auth_got',
                          '__got') for sect in sects]):
        bv.blocks_plugin_logger.log_info(f"{where}: Address is in an exempted section that does not contain stack blocks")
        return

    if len(bv.get_functions_containing(block_literal_insn.address)) == 0:
        bv.blocks_plugin_logger.log_warn(f"{where}: Address is not in any functions")
        return

    if isinstance(block_literal_insn, binja.HighLevelILVarInit):
        # The most common case where Binja knows nothing about the stack
        # variable.  The initialization with __NSConcreteStackBlock is a
        # HighLevelILVarInit.
        block_literal_var = block_literal_insn.dest
        isa_src = block_literal_insn.src
    elif isinstance(block_literal_insn, binja.HighLevelILAssign):
        # Sometimes use of the block in subsequent APIs with known signature
        # (e.g. __Block_copy) causes Binja to create a stack var at the stack
        # address of the block literal.  The initialization with
        # __NSConcreteStackBlock is a HighLevelILAssign.
        # HighLevelILAssign will also occur if stack space is used for
        # different purposes in different branches of a function.
        if isinstance(block_literal_insn.dest, binja.HighLevelILStructField):
            block_literal_var = block_literal_insn.dest.src.var
        elif isinstance(block_literal_insn.dest, binja.HighLevelILVar):
            block_literal_var = block_literal_insn.dest.var
        else:
            bv.blocks_plugin_logger.log_error(f"{where}: Assignment is not to a var or to a struct field")
            return
        isa_src = block_literal_insn.src
    else:
        bv.blocks_plugin_logger.log_error(f"{where}: Instruction is neither a var init nor an assign")
        return

    if block_literal_var.source_type != binja.VariableSourceType.StackVariableSourceType:
        bv.blocks_plugin_logger.log_warn(f"{where}: Assignment is not to a stack variable (var source_type is {block_literal_var.source_type!r})")
        return

    if not ((isinstance(isa_src, binja.HighLevelILImport) and \
                (isa_src.constant in sym_addrs)) or \
            (isinstance(isa_src, binja.HighLevelILConstPtr) and \
                (isa_src.constant in sym_addrs))):
        bv.blocks_plugin_logger.log_warn(f"{where}: RHS is not __NSConcreteStackBlock")
        return

    try:
        bl = BlockLiteral.from_stack(bv, block_literal_insn, block_literal_var, sym_addrs)
        bv.blocks_plugin_logger.log_info(str(bl))
        bd = BlockDescriptor(bv, bl.descriptor, bl.flags)
        bv.blocks_plugin_logger.log_info(str(bd))
        bl.annotate_literal(bd)
        bd.annotate_descriptor(bl)
        bd.annotate_layout_bytecode()
        bd.annotate_generic_helper_info_bytecode()
        bl.annotate_functions(bd)
    except BlockLiteral.NotABlockLiteralError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Not a block literal: {e}")
        return
    except BlockLiteral.FailedToFindFieldsError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Failed to find fields: {e}")
        return
    except BlockDescriptor.NotABlockDescriptorError as e:
        bv.blocks_plugin_logger.log_warn(f"{where}: Not a block descriptor: {e}")
        return
    except Exception as e:
        bv.blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return

    # XXX refactor byref handling

    # annotate stack byrefs

    try:
        if bd.imported_variables_size > 0 and len(bl.byref_indexes) > 0:

            # collect byref_srcs
            byref_srcs = []
            byref_indexes_set = set(bl.byref_indexes)
            for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(bl.insn.function, bl.insn.dest.src.var.identifier):
                if isinstance(insn.src, binja.HighLevelILAddressOf):
                    insn_src = insn.src
                else:
                    insn_src = None

                if insn.dest.member_index in byref_indexes_set:
                    byref_srcs.append((insn_src, insn.dest.member_index))

            # check number of byref_srcs
            byref_srcs_set = set([t[1] for t in byref_srcs])
            if len(byref_srcs_set) != len(byref_indexes_set):
                missing_indexes_set = byref_indexes_set - byref_srcs_set
                missing_indexes_str = ', '.join([str(idx) for idx in sorted(missing_indexes_set)])
                bv.blocks_plugin_logger.log_warn(f"{where}: Failed to find byref for struct member indexes {missing_indexes_str}, review manually")

            # process byref_srcs
            for byref_src, byref_member_index in byref_srcs:
                if byref_src is None:
                    bv.blocks_plugin_logger.log_warn(f"{where}: Byref for struct member index {byref_member_index} is not an AddressOf, review manually")
                    continue
                assert isinstance(byref_src, binja.HighLevelILAddressOf)
                if isinstance(byref_src.src, binja.HighLevelILVar):
                    var_id = byref_src.src.var.identifier
                else:
                    bv.blocks_plugin_logger.log_warn(f"{where}: Byref for struct member index {byref_member_index} and src {byref_src} is {type(byref_src.src).__name__}, review manually")
                    continue

                byref_insn = None
                for insn in bl.insn.function.instructions:
                    if isinstance(insn, binja.HighLevelILVarDeclare):
                        cand_var = insn.var
                    elif isinstance(insn, binja.HighLevelILVarInit):
                        if isinstance(insn.dest, binja.HighLevelILStructField):
                            continue
                        cand_var = insn.dest
                    else:
                        continue

                    if cand_var.identifier == var_id:
                        byref_insn = insn
                        byref_insn_var = cand_var
                        break

                else:
                    bv.blocks_plugin_logger.log_warn(f"{where}: Byref src var {byref_src} id {var_id:x} not found in function's var declarations and inits")
                    continue

                # So apparently this works; despite the reloads, byref_srcs are not invalidated, identifiers are still current.
                # Should that cease to be the case, we'll need to find next byref_src in a way that is robust to reloads.

                if not byref_insn_var.name.startswith("block_byref_"):
                    byref_insn_var.name = f"block_byref_{byref_insn_var.name}"

                byref_struct = binja.StructureBuilder.create()
                byref_struct.append(_parse_objc_type(bv, "Class"), "isa")
                byref_struct.append(bv.parse_type_string("void *forwarding")[0], "forwarding") # placeholder
                byref_struct.append(_parse_libclosure_type(bv, "enum Block_byref_flags"), "flags")
                byref_struct.append(bv.parse_type_string("uint32_t size")[0], "size")

                byref_insn_var.type = byref_struct
                byref_insn = bv.reload_hlil_instruction(byref_insn,
                        lambda insn: \
                                isinstance(insn, binja.HighLevelILVarDeclare) and \
                                str(insn.var.type).startswith('struct'))
                byref_insn_var = byref_insn.var

                # XXX Detect when there are multiple assignments to the same member_index
                # in different branches and warn accordingly.

                for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(byref_insn.function, byref_insn_var.identifier):
                    # 0 isa
                    # 1 forwarding
                    if insn.dest.member_index == 2:
                        if isinstance(insn.src, (binja.HighLevelILConst,
                                                 binja.HighLevelILConstPtr)):
                            byref_flags = insn.src.constant
                    elif insn.dest.member_index == 3:
                        if isinstance(insn.src, (binja.HighLevelILConst,
                                                 binja.HighLevelILConstPtr)):
                            byref_size = insn.src.constant
                try:
                    bv.blocks_plugin_logger.log_info(f"Block byref at {byref_insn.address:x} flags {byref_flags:08x} size {byref_size:#x}")
                except UnboundLocalError as e:
                    bv.blocks_plugin_logger.log_warn(f"Block byref at {byref_insn.address:x}: Failed to find flags or size assignments")
                    continue

                if byref_size > 0x1000:
                    bv.blocks_plugin_logger.log_warn(f"Block byref at {byref_insn.address:x}: Implausible size {byref_size:#x}")
                    continue

                byref_struct.width = byref_size

                if (byref_flags & BLOCK_BYREF_HAS_COPY_DISPOSE) != 0:
                    byref_struct.append(_get_libclosure_type(bv, "BlockByrefKeepFunction"), "keep")
                    byref_struct.append(_get_libclosure_type(bv, "BlockByrefDestroyFunction"), "destroy")
                byref_layout_nibble = (byref_flags & BLOCK_BYREF_LAYOUT_MASK)
                if byref_layout_nibble == BLOCK_BYREF_LAYOUT_EXTENDED:
                    byref_struct.append(bv.parse_type_string("void *layout")[0], "layout")
                    layout_index = byref_struct.index_by_name("layout")
                    byref_insn_var.type = byref_struct
                    byref_insn = bv.reload_hlil_instruction(byref_insn,
                            lambda insn: \
                                    isinstance(insn, binja.HighLevelILVarDeclare) and \
                                    str(insn.var.type).startswith('struct'))
                    byref_insn_var = byref_insn.var
                    byref_layout = None
                    for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(byref_insn.function, byref_insn_var.identifier):
                        if insn.dest.member_index == layout_index:
                            if isinstance(insn.src, (binja.HighLevelILConst,
                                                     binja.HighLevelILConstPtr)):
                                byref_layout = insn.src.constant
                                break
                    else:
                        bv.blocks_plugin_logger.log_warn(f"Block byref at {byref_insn.address:x}: Failed to find layout assignment")
                    if byref_layout is not None and byref_layout != 0:
                        if byref_layout < 0x1000:
                            # inline layout encoding
                            byref_layout_bytecode = None
                            byref_struct.replace(layout_index, bv.parse_type_string("uint64_t layout")[0], "layout")
                        else:
                            # out-of-line layout string
                            byref_layout_bytecode = bv.get_raw_string_at(byref_layout)
                            byref_struct.replace(layout_index, bv.parse_type_string("uint8_t const *layout")[0], "layout")
                    else:
                        byref_layout_bytecode = None
                    append_layout_fields(bv, byref_struct,
                                         BLOCK_GENERIC_HELPER_NONE, None, None,
                                         byref_layout is not None, byref_layout, byref_layout_bytecode)
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_NON_OBJECT:
                    byref_struct.append_with_offset_suffix(bv.parse_type_string("uint64_t non_object")[0], "non_object_")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_STRONG:
                    byref_struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "strong_ptr_")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_WEAK:
                    byref_struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "weak_ptr_")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_UNRETAINED:
                    byref_struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "unretained_ptr_")

                byref_struct_name = f"Block_byref_{byref_insn.address:x}"
                bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, byref_struct_name), byref_struct_name, byref_struct)
                byref_struct_type_name = f"struct {byref_struct_name}"
                byref_struct_type = bv.parse_type_string(byref_struct_type_name)[0]
                assert byref_struct_type is not None

                # propagate registered struct to forwarding self pointer
                byref_struct.replace(1, binja.Type.pointer(bv.arch, byref_struct_type), "forwarding")
                bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, byref_struct_name), byref_struct_name, byref_struct)
                byref_struct_type = bv.parse_type_string(byref_struct_type_name)[0]

                byref_insn_var.type = byref_struct_type
                byref_insn = bv.reload_hlil_instruction(byref_insn,
                        lambda insn: \
                                isinstance(insn, binja.HighLevelILVarDeclare) and \
                                str(insn.var.type).startswith('struct'))
                byref_insn_var = byref_insn.var

                # propagate byref type to block literal type
                byref_member_name = bl.struct_builder.members[byref_member_index].name
                assert byref_member_name.startswith("byref_ptr_")
                bl.struct_builder.replace(byref_member_index, binja.Type.pointer(bv.arch, byref_struct_type), byref_member_name)
                bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, bl.struct_name), bl.struct_name, bl.struct_builder)
                bl.struct_type = bv.parse_type_string(bl.struct_type_name)[0]

                # annotate functions
                if (byref_flags & BLOCK_BYREF_HAS_COPY_DISPOSE) != 0:
                    keep_index = byref_struct.index_by_name("keep")
                    destroy_index = byref_struct.index_by_name("destroy")
                    byref_keep = None
                    byref_destroy = None
                    for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(byref_insn.function, byref_insn_var.identifier):
                        if insn.dest.member_index == keep_index:
                            if isinstance(insn.src, (binja.HighLevelILConst,
                                                     binja.HighLevelILConstPtr)):
                                byref_keep = insn.src.constant
                        elif insn.dest.member_index == destroy_index:
                            if isinstance(insn.src, (binja.HighLevelILConst,
                                                     binja.HighLevelILConstPtr)):
                                byref_destroy = insn.src.constant
                    if byref_keep is None:
                        bv.blocks_plugin_logger.log_warn(f"Block byref at {byref_insn.address:x}: Failed to find keep assignment")
                    if byref_destroy is None:
                        bv.blocks_plugin_logger.log_warn(f"Block byref at {byref_insn.address:x}: Failed to find destroy assignment")
                    if byref_keep is None and byref_destroy is None:
                        continue

                    # Interleave annotation of the two functions in order to minimize
                    # the number of expensive calls to update_analysis_and_wait().
                    if byref_keep is not None:
                        keep_func = bv.get_function_at(byref_keep)
                    else:
                        keep_func = None
                    if byref_destroy is not None:
                        destroy_func = bv.get_function_at(byref_destroy)
                    else:
                        destroy_func
                    if keep_func is not None or destroy_func is not None:
                        if keep_func is not None:
                            keep_func.type = binja.Type.function(binja.Type.void(),
                                                                 [binja.Type.pointer(bv.arch, byref_struct_type),
                                                                  binja.Type.pointer(bv.arch, byref_struct_type)])
                        if destroy_func is not None:
                            destroy_func.type = binja.Type.function(binja.Type.void(),
                                                                    [binja.Type.pointer(bv.arch, byref_struct_type)])
                        bv.update_analysis_and_wait()

                        if keep_func is not None:
                            if len(keep_func.parameter_vars) >= 2:
                                keep_func.parameter_vars[0].set_name_async("dst")
                                keep_func.parameter_vars[1].set_name_async("src")
                        if destroy_func is not None:
                            if len(destroy_func.parameter_vars) >= 1:
                                destroy_func.parameter_vars[0].set_name_async("dst")
                        bv.update_analysis_and_wait()

                        if keep_func is not None:
                            if keep_func.name == f"sub_{keep_func.start:x}":
                                keep_func.name = f"sub_{keep_func.start:x}_byref_keep"

                        if destroy_func is not None:
                            if destroy_func.name == f"sub_{destroy_func.start:x}":
                                destroy_func.name = f"sub_{destroy_func.start:x}_byref_destroy"


    except Exception as e:
        bv.blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return


def annotate_all_global_blocks(bv, set_progress=None):
    sym_addrs = bv.get_symbol_addresses_set("__NSConcreteGlobalBlock")
    if len(sym_addrs) == 0:
        bv.blocks_plugin_logger.log_info("__NSConcreteGlobalBlock not found, target does not appear to contain any global blocks")
        return

    for sym_addr in sym_addrs:
        for addr in bv.get_data_refs(sym_addr):
            if set_progress is not None:
                set_progress(f"{addr:x}")
            annotate_global_block_literal(bv, addr, sym_addrs)


def annotate_all_stack_blocks(bv, set_progress=None):
    sym_addrs = bv.get_symbol_addresses_set("__NSConcreteStackBlock")
    if len(sym_addrs) == 0:
        bv.blocks_plugin_logger.log_info("__NSConcreteStackBlock not found, target does not appear to contain any stack blocks")
        return

    # We'd want to use get_code_refs here, but it is very unreliable.
    # Yielded refsrc objects often have only llil but not mlil or hlil;
    # .llil.hlil is also None, .llil.hlils contains the llil that matches,
    # sometimes multiple times.  The issue seems more frequent on but not
    # limited to arm64.
    #for refsrc in bv.get_code_refs(imp_sym.address):
    #    print(refsrc)
    #    print(refsrc.llil, refsrc.mlil, refsrc.hlil, refsrc.llil.hlil, refsrc.llil.hlils)

    for insn in bv.hlil_instructions:
        if not isinstance(insn, (binja.HighLevelILVarInit,
                                 binja.HighLevelILAssign)):
            continue
        if not isinstance(insn.src, (binja.HighLevelILImport,
                                     binja.HighLevelILConstPtr)):
            continue
        if insn.src.constant not in sym_addrs:
            continue
        if set_progress is not None:
            set_progress(f"{insn.address:x}")
        annotate_stack_block_literal(bv, insn, sym_addrs)


@shinobi.register_for_high_level_il_instruction("Blocks\\Annotate stack block here", is_valid=is_valid)
@shinobi.background_task("Blocks: Stack block")
@shinobi.undoable
def plugin_cmd_annotate_stack_block_literal_here(bv, block_literal_insn, set_progress=None):
    """
    Define a stack block literal here.
    """
    annotate_stack_block_literal(bv, block_literal_insn)


@shinobi.register_for_address("Blocks\\Annotate global block here", is_valid=is_valid)
@shinobi.background_task("Blocks: Global block")
@shinobi.undoable
def plugin_cmd_annotate_global_block_literal_here(bv, address, set_progress=None):
    """
    Define a global block literal here.
    """
    annotate_global_block_literal(bv, address)


@shinobi.register("Blocks\\Annotate all stack blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All stack blocks")
@shinobi.undoable
def plugin_cmd_annotate_all_stack_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteStackBlock and
    annotate stack blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_stack_blocks(bv, set_progress=set_progress)


@shinobi.register("Blocks\\Annotate all global blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All global blocks")
@shinobi.undoable
def plugin_cmd_annotate_all_global_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteGlobalBlock and
    annotate global blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_global_blocks(bv, set_progress=set_progress)


@shinobi.register("Blocks\\Annotate all blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All blocks")
@shinobi.undoable
def plugin_cmd_annotate_all_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteGlobalBlock and __NSConcreteStackBlock
    and annotate all blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_global_blocks(bv, set_progress=set_progress)
    annotate_all_stack_blocks(bv, set_progress=set_progress)


# This is no longer a useful command as the plugin no longer sets any comments.
# However, folks still have Binja databases with comments where having this
# command is still useful despite the plugin not adding these any longer.
@shinobi.register_for_address("Blocks\\Remove plugin comment here", is_valid=is_valid)
@shinobi.background_task("Blocks: Remove comment")
@shinobi.undoable
def plugin_cmd_remove_plugin_comment_here(bv, address, set_progress=None):
    """
    Remove global comment here.
    Useful to remove comments added by this plugin, e.g. after manually
    adding missing imported variables to block literals.
    """
    bv.set_comment_at(address, None)
