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
                return bv.x_parse_type(typestr)
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
            sym = bv.x_get_symbol_of_type(sym_name, sym_type)
            if sym is None or sym.address == 0:
                continue
            bv.x_make_data_var(sym.address, objc_class_type)
            break


def _blocks_plugin_logger(self):
    """
    Get this plugin's logger for the view.
    Create the logger if it does not exist yet.
    Monkey-patching this in to avoid having to pass around
    a separate logger with the same lifetime as the view.
    """
    logger = getattr(self, '_x_blocks_plugin_logger', None)
    if logger is None:
        logger = self.create_logger(_LOGGER_NAME)
        self._x_blocks_plugin_logger = logger
    return logger
binja.BinaryView.x_blocks_plugin_logger = property(_blocks_plugin_logger)


class Layout:
    """
    Represents a block literal or byref layout, describing the memory layout of
    the imported variables included in the block literal or byref.  In the case
    of the block literals, these are variables the block closes over (captures).
    """
    class Field:
        """
        Represents a single field, or series of identical fields.
        """
        def __init__(self, name_prefix, field_type, count=1, *, is_byref=False):
            self.name_prefix = name_prefix
            self.field_type = field_type
            self.count = count
            self.is_byref = is_byref

    @classmethod
    def from_generic_helper_info(cls, bv, generic_helper_type, generic_helper_info, generic_helper_info_bytecode):
        """
        Always returns a layout instance, which may be empty if there is no
        generic helper info available (generic_helper_type ==
        BLOCK_GENERIC_HELPER_NONE).
        """
        id_type = _parse_objc_type(bv, "id")

        fields = []

        if generic_helper_type == BLOCK_GENERIC_HELPER_INLINE:
            assert generic_helper_info_bytecode is None
            assert generic_helper_info is not None
            assert isinstance(generic_helper_info, int)
            assert (0xFFFFFFFFF00000FF & generic_helper_info) == 0

            n_strong_ptrs = (generic_helper_info >> 8) & 0xf
            n_block_ptrs = (generic_helper_info >> 12) & 0xf
            n_byref_ptrs = (generic_helper_info >> 16) & 0xf
            n_weak_ptrs = (generic_helper_info >> 20) & 0xf

            if n_strong_ptrs > 0:
                fields.append(Layout.Field("strong_ptr_", id_type, n_strong_ptrs))
            if n_block_ptrs > 0:
                fields.append(Layout.Field("block_ptr_", id_type, n_block_ptrs))
            if n_byref_ptrs > 0:
                fields.append(Layout.Field("byref_ptr_", id_type, n_byref_ptrs, is_byref=True))
            if n_weak_ptrs > 0:
                fields.append(Layout.Field("weak_ptr_", id_type, n_weak_ptrs))

        elif generic_helper_type == BLOCK_GENERIC_HELPER_OUTOFLINE:
            assert generic_helper_info_bytecode is not None

            for op in generic_helper_info_bytecode[1:]:
                opcode = (op & 0xf0) >> 4
                oparg = (op & 0x0f)
                if opcode == BCK_DONE:
                    break
                elif opcode == BCK_NON_OBJECT_BYTES:
                    fields.append(Layout.Field("non_object_", bv.x_parse_type(f"uint8_t [{oparg}]")))
                elif opcode == BCK_NON_OBJECT_WORDS:
                    fields.append(Layout.Field("non_object_", bv.x_parse_type("uint64_t"), oparg))
                elif opcode == BCK_STRONG:
                    fields.append(Layout.Field("strong_ptr_", id_type, oparg))
                elif opcode == BCK_BLOCK:
                    fields.append(Layout.Field("block_ptr_", id_type, oparg))
                elif opcode == BCK_BYREF:
                    fields.append(Layout.Field("byref_ptr_", id_type, oparg, is_byref=True))
                elif opcode == BCK_WEAK:
                    fields.append(Layout.Field("weak_ptr_", id_type, oparg))
                else:
                    bv.x_blocks_plugin_logger.log_warn(f"Unknown out-of-line generic helper op {op:#04x}")
                    break

        return cls(fields)

    @classmethod
    def from_layout(cls, bv, block_has_extended_layout, layout, layout_bytecode):
        """
        Always returns a layout instance, which may be empty if there is no
        layout information available (layout is None).
        """
        id_type = _parse_objc_type(bv, "id")

        fields = []

        if layout is not None and block_has_extended_layout and layout != 0:
            if layout < 0x1000:
                # inline layout encoding
                assert layout_bytecode is None

                n_strong_ptrs = (layout >> 8) & 0xf
                n_byref_ptrs = (layout >> 4) & 0xf
                n_weak_ptrs = layout & 0xf

                if n_strong_ptrs > 0:
                    fields.append(Layout.Field("strong_ptr_", id_type, n_strong_ptrs))
                if n_byref_ptrs > 0:
                    fields.append(Layout.Field("byref_ptr_", id_type, n_byref_ptrs, is_byref=True))
                if n_weak_ptrs > 0:
                    fields.append(Layout.Field("weak_ptr_", id_type, n_weak_ptrs))

            else:
                # out-of-line layout string
                assert layout_bytecode is not None

                for op in layout_bytecode:
                    opcode = (op & 0xf0) >> 4
                    oparg = (op & 0x0f)
                    if opcode == BLOCK_LAYOUT_ESCAPE:
                        break
                    elif opcode == BLOCK_LAYOUT_NON_OBJECT_BYTES:
                        fields.append(Layout.Field("non_object_", bv.x_parse_type(f"uint8_t [{oparg}]")))
                    elif opcode == BLOCK_LAYOUT_NON_OBJECT_WORDS:
                        fields.append(Layout.Field("non_object_", bv.x_parse_type("uint64_t"), oparg))
                    elif opcode == BLOCK_LAYOUT_STRONG:
                        fields.append(Layout.Field("strong_ptr_", id_type, oparg))
                    elif opcode == BLOCK_LAYOUT_BYREF:
                        fields.append(Layout.Field("byref_ptr_", id_type, oparg, is_byref=True))
                    elif opcode == BLOCK_LAYOUT_WEAK:
                        fields.append(Layout.Field("weak_ptr_", id_type, oparg))
                    elif opcode == BLOCK_LAYOUT_UNRETAINED:
                        fields.append(Layout.Field("unretained_ptr_", id_type, oparg))
                    else:
                        bv.x_blocks_plugin_logger.log_warn(f"Unknown out-of-line extended layout op {op:#04x}")
                        break

        return cls(fields)

    def __init__(self, fields):
        self._fields = fields

    @property
    def byref_count(self):
        return sum([f.count for f in self._fields if f.is_byref])

    @property
    def bytes_count(self):
        return sum([f.count * f.field_type.width for f in self._fields])

    def prefer_over(self, other):
        """
        Prefer more byrefs.
        If tied then prefer more bytes covered by fields.
        """
        if self.byref_count < other.byref_count:
            return False
        if self.bytes_count < other.bytes_count:
            return False
        return True

    def append_fields(self, struct):
        byref_indexes = []
        for field in self._fields:
            for _ in range(field.count):
                if field.is_byref:
                    byref_indexes.append(len(struct.members))
                struct.append_with_offset_suffix(field.field_type, field.name_prefix)
        return byref_indexes


class GeneratedStruct:
    def __init__(self, bv, builder, name):
        self._bv = bv

        self.name = name
        self.type_id = binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.name)

        t = self._bv.get_type_by_name(self.name)
        if t is not None:
            self._bv.x_blocks_plugin_logger.log_debug(f"GeneratedStruct: Type with {name=} already exists, using existing type")
            if self._bv.get_type_id(self.name) != self.type_id:
                self._bv.x_blocks_plugin_logger.log_warn(f"GeneratedStruct: Loaded type_id {self._bv.get_type_id(self.name)} differs from computed type_id {self.type_id}")
            self.builder = binja.StructureBuilder.create(t.members, packed=t.packed, width=t.width)
        else:
            self._bv.x_blocks_plugin_logger.log_debug(f"GeneratedStruct: Type with {name=} does not exist, defining new type")
            self.builder = builder
            bv.define_type(self.type_id, self.name, self.builder)

        self.type_name = f"struct {self.name}"
        self.type = bv.x_parse_type(self.type_name)
        assert self.type is not None

    @property
    def pointer_to_type(self):
        return binja.Type.pointer(self._bv.arch, self.type)

    def update_member_type(self, member_name_or_index, new_member_type, if_type=None):
        assert member_name_or_index is not None
        if isinstance(member_name_or_index, str):
            member_name = member_name_or_index
            member_index = self.builder.index_by_name(member_name)
            assert member_index is not None
        elif isinstance(member_name_or_index, int):
            member_index = member_name_or_index
            member_name = self.builder.members[member_index].name
            assert member_name is not None
        else:
            raise ValueError(f"member_name_or_index argument is of unexpected type {type(member_name_or_index).__name__}")
        if if_type is not None:
            if str(self.builder.members[member_index].type) != if_type:
                return
        self.builder.replace(member_index, new_member_type, member_name)
        self._bv.define_type(self.type_id, self.name, self.builder)
        self.type = self._bv.x_parse_type(self.type_name)
        assert self.type is not None

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

        bl_insn = bv.x_reload_hlil_instruction(bl_insn,
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

    def _warn(self, msg):
        self._bv.x_blocks_plugin_logger.log_warn(f"Block literal at {self.address:x}: {msg}")

    def annotate_literal(self, bd):
        """
        Annotate the block literal.
        """
        if self.is_stack_block:
            assert isinstance(self.insn, binja.HighLevelILAssign)
            assert isinstance(self.insn.dest, binja.HighLevelILStructField)
            assert isinstance(self.insn.dest.src, binja.HighLevelILVar)
            stack_var = self.insn.dest.src.var
            stack_var_type_name = str(stack_var.type)
            if stack_var_type_name.startswith("struct Block_literal_") and stack_var_type_name != bd.block_literal_struct.type_name:
                # Stack var has already been annotated for initialization code
                # at a different address, likely because multiple branches in
                # the function place a block at the same stack address.
                # Unfortunately, this seems to be a hypothetical situation
                # right now, as Binja does not seem to handle different use of
                # the same stack area by different branches gracefully.
                self._warn(f"Stack var {stack_var.name} already annotated with type {stack_var_type_name}; may need to split the stack var")
                return

            if not stack_var.name.startswith("stack_block_"):
                stack_var.name = f"stack_block_{stack_var.name}"
            stack_var.type = bd.block_literal_struct.type_name
            self.insn = self._bv.x_reload_hlil_instruction(self.insn,
                    lambda insn: \
                            isinstance(insn, binja.HighLevelILAssign) and \
                            isinstance(insn.dest, binja.HighLevelILStructField) and \
                            isinstance(insn.dest.src, binja.HighLevelILVar) and \
                            str(insn.dest.src.var.type).startswith('struct Block_literal_'))
        else:
            self.data_var.name = f"global_block_{self.address:x}"
            self.data_var.type = bd.block_literal_struct.type_name

    def annotate_invoke_function(self, bd):
        """
        Annotate the invoke function.
        """

        invoke_func = self._bv.get_function_at(self.invoke)
        if invoke_func is not None:
            # The signature type may be None if there was no signature field on
            # the descriptor or if we failed to parse its ObjC type string.
            invoke_func_type = bd.signature_type

            if invoke_func_type is None and len(invoke_func.parameter_vars) == 0:
                # If Binja did not pick up on any parameters, fall back to a vararg
                # signature.  We're not going to clobber any parameter types.
                invoke_func_type = binja.Type.function(binja.Type.void(),
                                                       [bd.block_literal_struct.pointer_to_type],
                                                       variable_arguments=True)

            if invoke_func_type is None:
                # Finally fall back to surgically setting return and first argument
                # types, leaving the other parameters undisturbed.
                invoke_func.return_type = binja.Type.void()
                invoke_func.parameter_vars[0].set_name_and_type_async("block", bd.block_literal_struct.pointer_to_type)
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
                invoke_func.type = invoke_func_type
                self._bv.update_analysis_and_wait()

                if len(invoke_func.parameter_vars) >= 1:
                    invoke_func.parameter_vars[0].name = "block"

            if invoke_func.name == f"sub_{invoke_func.start:x}":
                invoke_func.name = f"sub_{invoke_func.start:x}_block_invoke"

    def find_interesting_captures(self, bd):
        """
        Find interesting captures of this block literal:
        -   Captured stack byrefs and their source variables
        -   Captures of self
        """
        byref_captures = []
        self_captures = []

        if bd.imported_variables_size == 0:
            return byref_captures, self_captures

        byref_indexes_set = set(bd.byref_indexes)
        for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(self.insn.function, self.insn.dest.src.var.identifier):
            if insn.dest.member_index is None:
                # No field declared at offset insn.dest.offset.  We could try
                # to create fields automatically here, but let's leave it to
                # the user for now.
                continue

            if insn.dest.member_index in byref_indexes_set and isinstance(insn.src, binja.HighLevelILAddressOf):
                byref_captures.append((insn.dest.member_index, insn.src))

            if isinstance(insn.src, binja.HighLevelILVar) and insn.src.var.name == "self":
                self_captures.append((insn.dest.member_index, insn.src.var.type))

        byref_captures_set = set([t[0] for t in byref_captures])
        if len(byref_captures_set) != len(byref_indexes_set):
            missing_indexes_set = byref_indexes_set - byref_captures_set
            missing_indexes_str = ', '.join([str(idx) for idx in sorted(missing_indexes_set)])
            self._warn(f"Failed to find byref capture for struct member indexes {missing_indexes_str}, review manually")

        return byref_captures, self_captures


class BlockDescriptor:
    class NotABlockDescriptorError(Exception):
        pass

    def __init__(self, bv, bl):
        """
        Read block descriptor from data at bl.descriptor.
        """
        assert bl.address is not None and bl.address != 0
        assert bl.descriptor is not None and bl.descriptor != 0
        assert bl.flags is not None and bl.flags != 0

        self._bv = bv
        self.address = bl.descriptor
        self.block_address = bl.address
        self.block_flags = bl.flags

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
            if self.in_descriptor_flags & 0xFFFF0000 != self.block_flags & 0xFFFF0000 & ~BLOCK_SMALL_DESCRIPTOR:
                raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: block flags {self.block_flags:08x} inconsistent with in-descriptor flags {self.in_descriptor_flags:08x}")
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
                    self.layout_bytecode = self._bv.x_get_byte_string_at(self.layout)
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
                self.generic_helper_info_bytecode = self._bv.x_get_byte_string_at(self.generic_helper_info, min_len=1)
                if self.generic_helper_info_bytecode is None:
                    raise BlockDescriptor.NotABlockDescriptorError(f"Block descriptor at {self.address:x}: out-of-line generic helper info string does not exist")
            else:
                self.generic_helper_info_bytecode = None
        else:
            self.generic_helper_info = None
            self.generic_helper_info_bytecode = None

        self.block_descriptor_struct = self._generate_block_descriptor_struct()
        self.block_literal_struct, self.byref_indexes = self._generate_block_literal_struct()

        # propagate struct type to descriptor pointer on block literal
        self.block_literal_struct.update_member_type("descriptor", self.block_descriptor_struct.pointer_to_type, if_type="struct Block_descriptor_1*")

        # We need the block literal struct before parsing the signature because
        # we want to reference it for the block argument.
        if self.block_has_signature and self.signature != 0:
            self.signature_type = self._parse_signature(self._bv.get_ascii_string_at(self.signature, 0).raw)
        else:
            self.signature_type = None

        # propagate invoke function signature to invoke pointer on block literal
        if self.signature_type is not None:
            self.block_literal_struct.update_member_type("invoke", binja.Type.pointer(self._bv.arch, self.signature_type), if_type="void (*)(void*, ...)")

    def _parse_signature(self, signature_raw):
        if signature_raw is None:
            return None

        def _type_for_ctype(ctype):
            if ctype.endswith("!"):
                fallback = 'id'
                ctype = ctype.replace("!", "*")
            elif ctype.endswith("*"):
                fallback = 'void *'
            else:
                fallback = 'void'
            try:
                return self._bv.x_parse_type(ctype).with_confidence(254)
            except SyntaxError:
                # XXX if struct or union and we have member type info, create struct or union and retry
                return self._bv.x_parse_type(fallback).with_confidence(200)

        # This works well for most blocks, but because Binja does not
        # seem to support [Apple's variant of] AArch64 calling
        # conventions properly when things are passed in v registers or
        # on the stack, signatures are sometimes wrong.
        try:
            ctypes = objctypes.ObjCEncodedTypes(signature_raw).ctypes
            assert len(ctypes) > 0
            types = list(map(_type_for_ctype, ctypes))
            types[1] = self.block_literal_struct.pointer_to_type
            return binja.Type.function(types[0], types[1:])
        except NotImplementedError as e:
            self._bv.x_blocks_plugin_logger.log_error(f"Failed to parse ObjC type encoding {signature_raw!r}: {type(e).__name__}: {e}")
            return None

    def _generate_block_descriptor_struct(self):
        struct = binja.StructureBuilder.create()
        if self.reserved == 0:
            struct.append(self._bv.x_parse_type("uint64_t"), "reserved")
        else:
            assert self.in_descriptor_flags is not None
            struct.append(_parse_libclosure_type(self._bv, "enum Block_flags"), "in_descriptor_flags")
            struct.append(self._bv.x_parse_type("uint32_t"), "reserved")
        assert struct.width == 8
        struct.append(self._bv.x_parse_type("uint64_t"), "size")
        if self.block_has_copy_dispose:
            struct.append(_get_libclosure_type(self._bv, "BlockCopyFunction"), "copy")
            struct.append(_get_libclosure_type(self._bv, "BlockDisposeFunction"), "dispose")
        if self.block_has_signature:
            struct.append(self._bv.x_parse_type("char const *"), "signature")
            if self.layout is not None:
                if self.layout < 0x1000:
                    # inline layout encoding
                    struct.append(self._bv.x_parse_type("uint64_t"), "layout")
                else:
                    # out-of-line layout string
                    struct.append(self._bv.x_parse_type("uint8_t const *"), "layout")
            else:
                # Skip the layout field, see ctor for rationale.
                pass
        return GeneratedStruct(self._bv, struct, f"Block_descriptor_{self.address:x}")

    def _generate_block_literal_struct(self):
        # Packed because block layout bytecode can lead to misaligned words,
        # which according to comments in LLVM source code seems intentional.
        struct = binja.StructureBuilder.create(packed=True, width=self.size)
        struct.append(_parse_objc_type(self._bv, "Class"), "isa")
        struct.append(_parse_libclosure_type(self._bv, "enum Block_flags"), "flags")
        struct.append(self._bv.x_parse_type("uint32_t"), "reserved")
        struct.append(_get_libclosure_type(self._bv, "BlockInvokeFunction"), "invoke")
        struct.append(binja.Type.pointer(self._bv.arch, _parse_libclosure_type(self._bv, "struct Block_descriptor_1")), "descriptor") # placeholder
        if self.imported_variables_size > 0:
            generic_helper_layout = Layout.from_generic_helper_info(self._bv, self.generic_helper_type, self.generic_helper_info, self.generic_helper_info_bytecode)
            layout_layout = Layout.from_layout(self._bv, self.block_has_extended_layout, self.layout, self.layout_bytecode)
            if generic_helper_layout.prefer_over(layout_layout):
                self._bv.x_blocks_plugin_logger.log_debug("Preferring generic helper info over layout")
                chosen_layout = generic_helper_layout
            else:
                self._bv.x_blocks_plugin_logger.log_debug("Preferring layout over generic helper info")
                chosen_layout = layout_layout
            byref_indexes = chosen_layout.append_fields(struct)
        else:
            byref_indexes = []

        # A block descriptor can be used by 1..n block literals.  Block
        # literals sharing the same descriptor will have identical layout only
        # as far as described in the invoke signature, and only as far as
        # relevant to copy/dispose.  Annotation with a single struct type
        # shared by all block literals with the same descriptor has the benefit
        # of blocks being passed around having the same type everywhere.
        # However, as soon as one wants to propagate more specific types for
        # captures, e.g. `struct Foo *` instead of merely `id`, then a single
        # shared struct type works less well.  Therefore, using a separate
        # struct type for each block literal seems preferable.
        #
        # We still leave the struct generation in BlockDescriptor, since it is
        # largely based on information not available in BlockLiteral without
        # access to BlockDescriptor.
        return GeneratedStruct(self._bv, struct, f"Block_literal_{self.block_address:x}"), byref_indexes

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

    def annotate_descriptor(self):
        """
        Annotate block descriptor.
        """
        self._bv.x_make_data_var(self.address,
                                 self.block_descriptor_struct.type,
                                 f"block_descriptor_{self.address:x}")

        # annotate generic helper info
        if self.generic_helper_type in (BLOCK_GENERIC_HELPER_INLINE,
                                        BLOCK_GENERIC_HELPER_OUTOFLINE):
            if self.generic_helper_type == BLOCK_GENERIC_HELPER_INLINE:
                generic_helper_info_type = self._bv.x_parse_type("uint64_t")
            else:
                generic_helper_info_type = self._bv.x_parse_type("uint8_t const *")
            self._bv.x_make_data_var(self.address - self._bv.arch.address_size,
                                     generic_helper_info_type,
                                     f"block_descriptor_{self.address:x}_generic_helper_info")

    def annotate_layout_bytecode(self):
        """
        Annotate the out-of-line layout string, if one exists.
        """
        if self.block_has_signature and self.block_has_extended_layout and self.layout >= 0x1000:
            n = len(self.layout_bytecode)
            self._bv.x_make_data_var(self.layout,
                                     self._bv.x_parse_type(f"uint8_t [{n}]"),
                                     f"block_layout_{self.layout:x}")

    def annotate_generic_helper_info_bytecode(self):
        """
        Annotate the out-of-line generic helper info string, if one exists.
        """
        if self.generic_helper_type == BLOCK_GENERIC_HELPER_OUTOFLINE:
            n = len(self.generic_helper_info_bytecode)
            self._bv.x_make_data_var(self.generic_helper_info,
                                     self._bv.x_parse_type(f"uint8_t [{n}]"),
                                     f"block_generic_helper_info_{self.generic_helper_info:x}")

    def annotate_copy_dispose_functions(self):
        """
        Annotate copy and dispose functions, if they exist.  Expensive
        operations are only performed if the functions have not already been
        annotated.
        """
        if self.block_has_copy_dispose:
            # Interleave annotation of the two functions in order to minimize
            # the number of expensive calls to update_analysis_and_wait().
            copy_func = self._bv.get_function_at(self.copy)
            dispose_func = self._bv.get_function_at(self.dispose)
            if copy_func is None and dispose_func is None:
                return

            need_sync = False
            if copy_func is not None:
                if len(copy_func.parameter_vars) < 2 or not str(copy_func.parameter_vars[0].type).startswith("struct Block_literal_"):
                    copy_func.type = binja.Type.function(binja.Type.void(),
                                                         [self.block_literal_struct.pointer_to_type,
                                                          self.block_literal_struct.pointer_to_type])
                    need_sync = True
            if dispose_func is not None:
                if len(dispose_func.parameter_vars) < 1 or not str(dispose_func.parameter_vars[0].type).startswith("struct Block_literal_"):
                    dispose_func.type = binja.Type.function(binja.Type.void(),
                                                            [self.block_literal_struct.pointer_to_type])
                    need_sync = True
            if need_sync:
                self._bv.update_analysis_and_wait()

            need_sync = False
            if copy_func is not None:
                if len(copy_func.parameter_vars) >= 2:
                    if copy_func.parameter_vars[0].name != "dst":
                        copy_func.parameter_vars[0].set_name_async("dst")
                        need_sync = True
                    if copy_func.parameter_vars[1].name != "src":
                        copy_func.parameter_vars[1].set_name_async("src")
                        need_sync = True
            if dispose_func is not None:
                if len(dispose_func.parameter_vars) >= 1:
                    if dispose_func.parameter_vars[0].name != "dst":
                        dispose_func.parameter_vars[0].set_name_async("dst")
                        need_sync = True
            if need_sync:
                self._bv.update_analysis_and_wait()

            if copy_func is not None:
                if copy_func.name == f"sub_{copy_func.start:x}":
                    copy_func.name = f"sub_{copy_func.start:x}_block_copy"

            if dispose_func is not None:
                if dispose_func.name == f"sub_{dispose_func.start:x}":
                    dispose_func.name = f"sub_{dispose_func.start:x}_block_dispose"


class BlockByref:
    class NotABlockByrefError(Exception):
        pass

    class FailedToFindFieldsError(Exception):
        pass

    def __init__(self, bv, byref_insn, byref_insn_var, byref_member_index=None, bd=None):
        """
        Parse and annotate stack byref.

        if bd is not None, update the pointer type of block literal struct
        member at index byref_member_index to be a pointer to the byref's
        layout type.
        """

        self._bv = bv
        self.byref_insn = byref_insn
        self.byref_insn_var = byref_insn_var
        self.address = self.byref_insn.address
        where = f"Block byref at {self.address:x}"

        # So apparently this works; despite the reloads, byref_srcs are not
        # invalidated, identifiers are still current.  Should that cease to be
        # the case, we'll need to find next byref_src in a way that is robust
        # to reloads.

        if not self.byref_insn_var.name.startswith("block_byref_"):
            self.byref_insn_var.name = f"block_byref_{self.byref_insn_var.name}"

        struct = binja.StructureBuilder.create()
        struct.append(_parse_objc_type(bv, "Class"), "isa")
        struct.append(self._bv.x_parse_type("void *"), "forwarding") # placeholder
        struct.append(_parse_libclosure_type(bv, "enum Block_byref_flags"), "flags")
        struct.append(self._bv.x_parse_type("uint32_t"), "size")

        self.byref_insn_var.type = struct
        self.byref_insn = self._bv.x_reload_hlil_instruction(self.byref_insn,
                lambda insn: \
                        isinstance(insn, binja.HighLevelILVarDeclare) and \
                        str(insn.var.type).startswith('struct'))
        self.byref_insn_var = self.byref_insn.var

        # XXX Detect when there are multiple assignments to the same member_index
        # in different branches and warn accordingly.

        for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(self.byref_insn.function, self.byref_insn_var.identifier):
            # 0 isa
            # 1 forwarding
            if insn.dest.member_index == 2:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    self.flags = insn.src.constant
            elif insn.dest.member_index == 3:
                if isinstance(insn.src, (binja.HighLevelILConst,
                                         binja.HighLevelILConstPtr)):
                    self.size = insn.src.constant

        for field in ('flags', 'size'):
            if getattr(self, field, None) is None:
                raise BlockByref.FailedToFindFieldsError(f"{field} for {where}, likely due to complex HLIL")

        assert self._bv.arch.address_size == 8
        if self.size < 0x18:
            raise BlockByref.NotABlockByrefError(f"{where}: Size too small ({self.size:#x} < 0x18)")
        if self.size > 0x1000:
            raise BlockByref.NotABlockByrefError(f"{where}: Size implausibly large ({self.size:#x} > 0x1000)")

        struct.width = self.size

        if (self.flags & BLOCK_BYREF_HAS_COPY_DISPOSE) != 0:
            struct.append(_get_libclosure_type(bv, "BlockByrefKeepFunction"), "keep")
            struct.append(_get_libclosure_type(bv, "BlockByrefDestroyFunction"), "destroy")
        byref_layout_nibble = (self.flags & BLOCK_BYREF_LAYOUT_MASK)
        if byref_layout_nibble == BLOCK_BYREF_LAYOUT_EXTENDED:
            struct.append(self._bv.x_parse_type("void *"), "layout")
            layout_index = struct.index_by_name("layout")
            self.byref_insn_var.type = struct
            self.byref_insn = self._bv.x_reload_hlil_instruction(self.byref_insn,
                    lambda insn: \
                            isinstance(insn, binja.HighLevelILVarDeclare) and \
                            str(insn.var.type).startswith('struct'))
            self.byref_insn_var = self.byref_insn.var
            byref_layout = None
            for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(self.byref_insn.function, self.byref_insn_var.identifier):
                if insn.dest.member_index == layout_index:
                    if isinstance(insn.src, (binja.HighLevelILConst,
                                             binja.HighLevelILConstPtr)):
                        byref_layout = insn.src.constant
                        break
            else:
                self._bv.x_blocks_plugin_logger.log_warn(f"{where}: Failed to find layout assignment")
            if byref_layout is not None and byref_layout != 0:
                if byref_layout < 0x1000:
                    # inline layout encoding
                    byref_layout_bytecode = None
                    struct.replace(layout_index, self._bv.x_parse_type("uint64_t"), "layout")
                else:
                    # out-of-line layout string
                    byref_layout_bytecode = self._bv.x_get_byte_string_at(byref_layout)
                    struct.replace(layout_index, self._bv.x_parse_type("uint8_t const *"), "layout")
            else:
                byref_layout_bytecode = None
            byref_layout_layout = Layout.from_layout(bv, True, byref_layout, byref_layout_bytecode)
            byref_layout_layout.append_fields(struct)
        elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_NON_OBJECT:
            struct.append_with_offset_suffix(self._bv.x_parse_type("uint64_t"), "non_object_")
        elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_STRONG:
            struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "strong_ptr_")
        elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_WEAK:
            struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "weak_ptr_")
        elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_UNRETAINED:
            struct.append_with_offset_suffix(_parse_objc_type(bv, "id"), "unretained_ptr_")

        self.byref_struct = GeneratedStruct(bv, struct, f"Block_byref_{self.byref_insn.address:x}")

        # propagate registered struct to forwarding self pointer
        self.byref_struct.update_member_type("forwarding", self.byref_struct.pointer_to_type)

        self.byref_insn_var.type = self.byref_struct.type
        self.byref_insn = self._bv.x_reload_hlil_instruction(self.byref_insn,
                lambda insn: \
                        isinstance(insn, binja.HighLevelILVarDeclare) and \
                        str(insn.var.type).startswith('struct'))
        self.byref_insn_var = self.byref_insn.var

        # propagate byref type to block literal type
        # different block literals might propagate different byrefs to the struct type
        if bd is not None:
            bd.block_literal_struct.update_member_type(byref_member_index, self.byref_struct.pointer_to_type, if_type="id")

    def __str__(self):
        return f"Block byref at {self.address:x} flags {self.flags:08x} size {self.size:#x}"

    def annotate_keep_destroy_functions(self):
        """
        Annotate the byref's keep and destroy functions.
        """

        if (self.flags & BLOCK_BYREF_HAS_COPY_DISPOSE) != 0:
            keep_index = self.byref_struct.builder.index_by_name("keep")
            destroy_index = self.byref_struct.builder.index_by_name("destroy")
            byref_keep = None
            byref_destroy = None
            for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(self.byref_insn.function, self.byref_insn_var.identifier):
                if insn.dest.member_index == keep_index:
                    if isinstance(insn.src, (binja.HighLevelILConst,
                                             binja.HighLevelILConstPtr)):
                        byref_keep = insn.src.constant
                elif insn.dest.member_index == destroy_index:
                    if isinstance(insn.src, (binja.HighLevelILConst,
                                             binja.HighLevelILConstPtr)):
                        byref_destroy = insn.src.constant
            if byref_keep is None:
                self._bv.x_blocks_plugin_logger.log_warn(f"Block byref at {self.address:x}: Failed to find keep assignment")
            if byref_destroy is None:
                self._bv.x_blocks_plugin_logger.log_warn(f"Block byref at {self.address:x}: Failed to find destroy assignment")
            if byref_keep is None and byref_destroy is None:
                return

            # Interleave annotation of the two functions in order to minimize
            # the number of expensive calls to update_analysis_and_wait().
            if byref_keep is not None:
                keep_func = self._bv.get_function_at(byref_keep)
            else:
                keep_func = None
            if byref_destroy is not None:
                destroy_func = self._bv.get_function_at(byref_destroy)
            else:
                destroy_func
            if keep_func is not None or destroy_func is not None:
                need_sync = False
                if keep_func is not None:
                    if len(keep_func.parameter_vars) < 2 or \
                            not str(keep_func.parameter_vars[0].type).startswith("struct Block_byref_"):
                        keep_func.type = binja.Type.function(binja.Type.void(),
                                                             [self.byref_struct.pointer_to_type,
                                                              self.byref_struct.pointer_to_type])
                        need_sync = True
                if destroy_func is not None:
                    if len(destroy_func.parameter_vars) < 1 or \
                            not str(destroy_func.parameter_vars[0].type).startswith("struct Block_byref_"):
                        destroy_func.type = binja.Type.function(binja.Type.void(),
                                                                [self.byref_struct.pointer_to_type])
                        need_sync = True
                if need_sync:
                    self._bv.update_analysis_and_wait()

                need_sync = False
                if keep_func is not None:
                    if len(keep_func.parameter_vars) >= 2:
                        if keep_func.parameter_vars[0].name != "dst":
                            keep_func.parameter_vars[0].set_name_async("dst")
                            need_sync = True
                        if keep_func.parameter_vars[1].name != "src":
                            keep_func.parameter_vars[1].set_name_async("src")
                            need_sync = True
                if destroy_func is not None:
                    if len(destroy_func.parameter_vars) >= 1:
                        if destroy_func.parameter_vars[0].name != "dst":
                            destroy_func.parameter_vars[0].set_name_async("dst")
                            need_sync = True
                if need_sync:
                    self._bv.update_analysis_and_wait()

                if keep_func is not None:
                    if keep_func.name == f"sub_{keep_func.start:x}":
                        keep_func.name = f"sub_{keep_func.start:x}_byref_keep"

                if destroy_func is not None:
                    if destroy_func.name == f"sub_{destroy_func.start:x}":
                        destroy_func.name = f"sub_{destroy_func.start:x}_byref_destroy"


def annotate_global_block_literal(bv, block_literal_addr, sym_addrs=None):
    where = f"Global block {block_literal_addr:x}"

    bv.x_blocks_plugin_logger.log_debug(f"Annotating {where}")

    if sym_addrs is None:
        sym_addrs = bv.x_get_symbol_addresses_set("__NSConcreteGlobalBlock")
        if len(sym_addrs) == 0:
            bv.x_blocks_plugin_logger.log_info("__NSConcreteGlobalBlock not found, target does not appear to contain any global blocks")
            return

    sects = bv.get_sections_at(block_literal_addr)
    if sects is None or len(sects) == 0:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Address is not in a section")
        return
    if any([sect.name in ('libsystem_blocks.dylib::__objc_classlist',
                          'libsystem_blocks.dylib::__objc_nlclslist') for sect in sects]):
        bv.x_blocks_plugin_logger.log_info(f"{where}: Address is in an exempted section that does not contain global blocks")
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
        bv.x_blocks_plugin_logger.log_error(f"{where}: Data var has value {data_var_value} of type {type(data_var_value).__name__}, expected int, fix plugin")
        return
    if data_var_value not in sym_addrs:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Data var has value {data_var_value:x} instead of __NSConcreteGlobalBlock")
        return

    try:
        bl = BlockLiteral.from_data(bv, block_literal_data_var, sym_addrs)
        bv.x_blocks_plugin_logger.log_info(str(bl))
        bd = BlockDescriptor(bv, bl)
        bv.x_blocks_plugin_logger.log_info(str(bd))
        bl.annotate_literal(bd)
        bd.annotate_descriptor()
        bd.annotate_layout_bytecode()
        bd.annotate_generic_helper_info_bytecode()
        bd.annotate_copy_dispose_functions()
        bl.annotate_invoke_function(bd)
    except BlockLiteral.NotABlockLiteralError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Not a block literal: {e}")
        return
    except BlockLiteral.FailedToFindFieldsError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Failed to find fields: {e}")
        return
    except BlockDescriptor.NotABlockDescriptorError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Not a block descriptor: {e}")
        return
    except Exception as e:
        bv.x_blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return


def annotate_stack_block_literal(bv, block_literal_insn, sym_addrs=None):
    where = f"Stack block {block_literal_insn.address:x}"

    bv.x_blocks_plugin_logger.log_debug(f"Annotating {where}")

    if sym_addrs is None:
        sym_addrs = bv.x_get_symbol_addresses_set("__NSConcreteStackBlock")
        if len(sym_addrs) == 0:
            bv.x_blocks_plugin_logger.log_info("__NSConcreteStackBlock not found, target does not appear to contain any stack blocks")
            return

    sects = bv.get_sections_at(block_literal_insn.address)
    if sects is None or len(sects) == 0:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Address is not in a section")
        return
    if any([sect.name in ('__auth_got',
                          '__got') for sect in sects]):
        bv.x_blocks_plugin_logger.log_info(f"{where}: Address is in an exempted section that does not contain stack blocks")
        return

    if len(bv.get_functions_containing(block_literal_insn.address)) == 0:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Address is not in any functions")
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
            bv.x_blocks_plugin_logger.log_error(f"{where}: Assignment is not to a var or to a struct field")
            return
        isa_src = block_literal_insn.src
    else:
        bv.x_blocks_plugin_logger.log_error(f"{where}: Instruction is neither a var init nor an assign")
        return

    if block_literal_var.source_type != binja.VariableSourceType.StackVariableSourceType:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Assignment is not to a stack variable (var source_type is {block_literal_var.source_type!r})")
        return

    if not ((isinstance(isa_src, binja.HighLevelILImport) and \
                (isa_src.constant in sym_addrs)) or \
            (isinstance(isa_src, binja.HighLevelILConstPtr) and \
                (isa_src.constant in sym_addrs))):
        bv.x_blocks_plugin_logger.log_warn(f"{where}: RHS is not __NSConcreteStackBlock")
        return

    try:
        bl = BlockLiteral.from_stack(bv, block_literal_insn, block_literal_var, sym_addrs)
        bv.x_blocks_plugin_logger.log_info(str(bl))
        bd = BlockDescriptor(bv, bl)
        bv.x_blocks_plugin_logger.log_info(str(bd))
        bl.annotate_literal(bd)
        bd.annotate_descriptor()
        bd.annotate_layout_bytecode()
        bd.annotate_generic_helper_info_bytecode()
        bd.annotate_copy_dispose_functions()
        bl.annotate_invoke_function(bd)

        byref_captures, self_captures = bl.find_interesting_captures(bd)
        for member_index, byref_src in byref_captures:
            annotate_stack_byref(bv, bl.insn.function, None, byref_src, bl.address, member_index, bd)
        for member_index, self_type in self_captures:
            bd.block_literal_struct.update_member_type(member_index, self_type, if_type="id")

    except BlockLiteral.NotABlockLiteralError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Not a block literal: {e}")
        return
    except BlockLiteral.FailedToFindFieldsError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Failed to find fields: {e}")
        return
    except BlockDescriptor.NotABlockDescriptorError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Not a block descriptor: {e}")
        return
    except Exception as e:
        bv.x_blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return


def annotate_stack_byref(bv, byref_function,
                         byref_insn=None,
                         byref_src=None, block_literal_address=None, byref_member_index=None, bd=None):

    if byref_insn is None:
        # came here from block literal byref member
        where = f"Stack byref for struct member {byref_member_index} of block literal at {block_literal_address:x}"
        bv.x_blocks_plugin_logger.log_debug(f"Annotating {where}")

        assert byref_src is not None
        assert block_literal_address is not None
        assert byref_member_index is not None
        assert bd is not None

        # find var_id from byref_src
        assert isinstance(byref_src, binja.HighLevelILAddressOf)
        if isinstance(byref_src.src, binja.HighLevelILVar):
            var_id = byref_src.src.var.identifier
        else:
            bv.x_blocks_plugin_logger.log_warn(f"{where}: Source {byref_src} is {type(byref_src.src).__name__}, review manually")
            return

    else:
        # came here from byref here plugin command
        where = f"Stack byref at {byref_insn.address:x}"
        bv.x_blocks_plugin_logger.log_debug(f"Annotating {where}")

        assert byref_src is None
        assert block_literal_address is None
        assert byref_member_index is None
        assert bd is None

        # find var_id from byref_insn
        if isinstance(byref_insn, binja.HighLevelILVarInit):
            var_id = byref_insn.dest.identifier
        elif isinstance(byref_insn, binja.HighLevelILAssign):
            if not isinstance(byref_insn.dest, binja.HighLevelILVar):
                bv.x_blocks_plugin_logger.log_error(f"{where}: Instruction {byref_insn} dest {byref_insn.dest} is {type(byref_insn.dest).__name__}, expected HighLevelILVar")
                return
            var_id = byref_insn.dest.var.identifier
        else:
            bv.x_blocks_plugin_logger.log_error(f"{where}: Instruction {byref_insn} is {type(byref_insn).__name__}, expected HighLevelILVarInit or HighLevelILAssign")
            return

    # Reload predicates in BlockByref depend on byref_insn being the
    # declaration or initialization, not some random other instruction.
    for insn in byref_function.instructions:
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
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Source var {byref_src} id {var_id:x} not found in function, review manually")
        return

    assert byref_insn is not None
    assert byref_insn_var is not None

    try:
        bb = BlockByref(bv, byref_insn, byref_insn_var, byref_member_index, bd)
        bv.x_blocks_plugin_logger.log_info(str(bb))
        bb.annotate_keep_destroy_functions()
    except BlockByref.NotABlockByrefError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Not a block byref: {e}")
        return
    except BlockByref.FailedToFindFieldsError as e:
        bv.x_blocks_plugin_logger.log_warn(f"{where}: Failed to find byref fields: {e}")
        return
    except Exception as e:
        bv.x_blocks_plugin_logger.log_error(f"{where}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        return


def annotate_all_global_blocks(bv, set_progress=None):
    sym_addrs = bv.x_get_symbol_addresses_set("__NSConcreteGlobalBlock")
    if len(sym_addrs) == 0:
        bv.x_blocks_plugin_logger.log_info("__NSConcreteGlobalBlock not found, target does not appear to contain any global blocks")
        return

    try:
        for sym_addr in sym_addrs:
            for addr in bv.get_data_refs(sym_addr):
                if set_progress is not None:
                    set_progress(f"{addr:x}")
                annotate_global_block_literal(bv, addr, sym_addrs)
    except shinobi.Task.Cancelled:
        pass


def annotate_all_stack_blocks(bv, set_progress=None):
    sym_addrs = bv.x_get_symbol_addresses_set("__NSConcreteStackBlock")
    if len(sym_addrs) == 0:
        bv.x_blocks_plugin_logger.log_info("__NSConcreteStackBlock not found, target does not appear to contain any stack blocks")
        return

    # We'd want to use get_code_refs here, but it is very unreliable.
    # Yielded refsrc objects often have only llil but not mlil or hlil;
    # .llil.hlil is also None, .llil.hlils contains the llil that matches,
    # sometimes multiple times.  The issue seems more frequent on but not
    # limited to arm64.
    #for refsrc in bv.get_code_refs(imp_sym.address):
    #    print(refsrc)
    #    print(refsrc.llil, refsrc.mlil, refsrc.hlil, refsrc.llil.hlil, refsrc.llil.hlils)

    try:
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
    except shinobi.Task.Cancelled:
        pass


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


@shinobi.register_for_high_level_il_instruction("Blocks\\Annotate stack byref here", is_valid=is_valid)
@shinobi.background_task("Blocks: Stack byref")
@shinobi.undoable
def plugin_cmd_annotate_stack_byref_here(bv, byref_insn, set_progress=None):
    """
    Define a stack byref here.
    """
    annotate_stack_byref(bv, byref_insn.function, byref_insn)


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
