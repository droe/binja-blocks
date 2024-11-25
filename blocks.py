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

from . import shinobi
from . import objctypes


def is_valid(bv, arg=None):
    return bv.arch.name in (
        'aarch64',
        'x86_64',
        #'armv7',
        #'x86',
    )


_TYPE_ID_SOURCE = "binja-blocks"


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
enum BLOCK_LITERAL_FLAGS : uint32_t {
    BLOCK_DEALLOCATING              = 0x0001U,       // runtime
    BLOCK_REFCOUNT_MASK             = 0xfffeU,       // runtime
    BLOCK_INLINE_LAYOUT_STRING      = 1U << 21,      // compiler
    BLOCK_SMALL_DESCRIPTOR          = 1U << 22,      // compiler
    BLOCK_IS_NOESCAPE               = 1U << 23,      // compiler
    BLOCK_NEEDS_FREE                = 1U << 24,      // runtime
    BLOCK_HAS_COPY_DISPOSE          = 1U << 25,      // compiler
    BLOCK_HAS_CTOR                  = 1U << 26,      // compiler
    BLOCK_IS_GC                     = 1U << 27,      // runtime
    BLOCK_IS_GLOBAL                 = 1U << 28,      // compiler
    BLOCK_USE_STRET                 = 1U << 29,      // compiler
    BLOCK_HAS_SIGNATURE             = 1U << 30,      // compiler
    BLOCK_HAS_EXTENDED_LAYOUT       = 1U << 31,      // compiler
};

enum BLOCK_BYREF_FLAGS : uint32_t {
    BLOCK_BYREF_DEALLOCATING        = 0x0001U,     // runtime
    BLOCK_BYREF_REFCOUNT_MASK       = 0xfffeU,     // runtime
    BLOCK_BYREF_NEEDS_FREE          = 1U << 24,    // runtime
    BLOCK_BYREF_HAS_COPY_DISPOSE    = 1U << 25,    // compiler
    BLOCK_BYREF_IS_GC               = 1U << 27,    // runtime
    BLOCK_BYREF_LAYOUT_MASK         = 7U << 28,    // compiler
    BLOCK_BYREF_LAYOUT_EXTENDED     = 1U << 28,    // compiler
    BLOCK_BYREF_LAYOUT_NON_OBJECT   = 2U << 28,    // compiler
    BLOCK_BYREF_LAYOUT_STRONG       = 3U << 28,    // compiler
    BLOCK_BYREF_LAYOUT_WEAK         = 4U << 28,    // compiler
    BLOCK_BYREF_LAYOUT_UNRETAINED   = 5U << 28,    // compiler
};

typedef void(*BlockCopyFunction)(void *, const void *);
typedef void(*BlockDisposeFunction)(const void *);
typedef void(*BlockInvokeFunction)(void *, ...);

struct Block_byref_1 {
    Class isa;
    struct Block_byref_1 *forwarding;
    volatile uint32_t flags;
    uint32_t size;
};

typedef void(*BlockByrefKeepFunction)(struct Block_byref*, struct Block_byref*);
typedef void(*BlockByrefDestroyFunction)(struct Block_byref *);

struct Block_byref_2 {
    BlockByrefKeepFunction byref_keep;
    BlockByrefDestroyFunction byref_destroy;
};

struct Block_byref_3 {
    const char *layout;
};

struct Block_descriptor_1 {
    uint64_t reserved;
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
    volatile uint32_t flags;
    uint32_t reserved;
    BlockInvokeFunction invoke;
    struct Block_descriptor_1 *descriptor;
    // ... imported variables
};
"""

BLOCK_HAS_EXTENDED_LAYOUT       = 0x80000000
BLOCK_HAS_SIGNATURE             = 0x40000000
BLOCK_IS_GLOBAL                 = 0x10000000
BLOCK_HAS_COPY_DISPOSE          = 0x02000000

BLOCK_BYREF_HAS_COPY_DISPOSE    = 0x02000000
BLOCK_BYREF_LAYOUT_MASK         = 0x70000000
BLOCK_BYREF_LAYOUT_EXTENDED     = 0x10000000
BLOCK_BYREF_LAYOUT_NON_OBJECT   = 0x20000000
BLOCK_BYREF_LAYOUT_STRONG       = 0x30000000
BLOCK_BYREF_LAYOUT_WEAK         = 0x40000000
BLOCK_BYREF_LAYOUT_UNRETAINED   = 0x50000000


def _get_custom_type(bv, name, source):
    type_ = bv.get_type_by_name(name)
    if type_ is not None:
        return type_
    types = bv.parse_types_from_string(source)
    bv.define_types([(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, k), k, v) for k, v in types.types.items()], None)
    type_ = bv.get_type_by_name(name)
    assert type_ is not None
    return type_


def _get_objc_type(bv, name):
    """
    These are only loaded by Binary Ninja if it detects Objective C.
    However, libclosure can be used without Objective C and we still
    need these types.
    """
    return _get_custom_type(bv, name, _OBJC_TYPE_SOURCE)


def _get_libclosure_type(bv, name):
    """
    Get a type shipped with the plugin.
    On first use, will define all types
    come with the plugin.
    """
    # Make sure the ObjC types we use in _LIBCLOSURE_TYPE_SOURCE
    # are present before parsing.
    _ = _get_objc_type(bv, "Class")
    return _get_custom_type(bv, name, _LIBCLOSURE_TYPE_SOURCE)


def _define_ns_concrete_block_imports(bv):
    """
    For some reason, Binary Ninja does not reliably define all external symbols.
    Make sure __NSConcreteGlobalBlock and __NSConcreteStackBlock are defined
    appropriately.
    """
    class_type = _get_objc_type(bv, "Class")
    for sym_name in ("__NSConcreteGlobalBlock", "__NSConcreteStackBlock"):
        ext_sym = shinobi.get_symbol_of_type(bv, sym_name, binja.SymbolType.ExternalSymbol)
        data_var = bv.get_data_var_at(ext_sym.address)
        if data_var is None:
            bv.define_data_var(ext_sym.address, class_type)
        else:
            data_var.type = class_type


class BlockLiteral:
    @classmethod
    def from_data(cls, bv, bl_data_var):
        """
        Read block literal from data.
        """
        is_stack_block = False
        br = binja.BinaryReader(bv)
        br.seek(bl_data_var.address)
        isa = br.read64()
        flags = br.read32()
        reserved = br.read32()
        invoke = br.read64()
        descriptor = br.read64()
        return cls(bv, is_stack_block, bl_data_var, isa, flags, reserved, invoke, descriptor)

    @classmethod
    def from_stack(cls, bv, bl_insn):
        is_stack_block = True
        bl_insn.dest.type = _get_libclosure_type(bv, "Block_literal")
        bl_insn = shinobi.reload_hlil_instruction(bv, bl_insn)
        for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(bl_insn.function, bl_insn.var.identifier):
            if insn.dest.member_index == 0:
                assert isinstance(insn.src, binja.HighLevelILImport)
                assert str(insn.src) == '__NSConcreteStackBlock'
                isa = insn.src.address
            elif insn.dest.member_index == 1:
                assert isinstance(insn.src, binja.HighLevelILConst)
                flags = insn.src.constant
            elif insn.dest.member_index == 2:
                assert isinstance(insn.src, binja.HighLevelILConst)
                reserved = insn.src.constant
            elif insn.dest.member_index == 3:
                assert isinstance(insn.src, binja.HighLevelILConstPtr)
                invoke = insn.src.constant
            elif insn.dest.member_index == 4:
                assert isinstance(insn.src, binja.HighLevelILConstPtr)
                descriptor = insn.src.constant
            else:
                # We don't know if the members are assigned in-order,
                # so we cannot rely on having descriptor and hence
                # size available.  As a result, do not attempt to pick
                # up imported variables here.  We'll need another pass
                # for that later.
                pass
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
        struct = binja.StructureBuilder.create()
        struct.append(_get_objc_type(self._bv, "Class"), "isa")
        struct.append(self._bv.parse_type_string(f"volatile uint32_t flags")[0], "flags")
        struct.append(self._bv.parse_type_string(f"uint32_t reserved")[0], "reserved")
        struct.append(_get_libclosure_type(self._bv, "BlockInvokeFunction"), "invoke")
        struct.append(binja.Type.pointer(self._bv.arch, _get_libclosure_type(self._bv, "Block_descriptor_1")), "descriptor")
        if bd.imported_variables_size > 0:
            if bd.layout != 0 and bd.layout < 0x1000:
                for i in range(bd.n_strong_ptrs):
                    struct.append(_get_objc_type(self._bv, "id"), f"strong_ptr_{i}")
                for i in range(bd.n_byref_ptrs):
                    struct.append(_get_objc_type(self._bv, "id"), f"byref_ptr_{i}")
                for i in range(bd.n_weak_ptrs):
                    struct.append(_get_objc_type(self._bv, "id"), f"weak_ptr_{i}")
        self.struct_builder = struct
        self.struct_name = f"Block_literal_{self.address:x}"
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.struct_name), self.struct_name, self.struct_builder)
        self.struct_type_name = f"struct {self.struct_name}"
        self.struct_type = self._bv.parse_type_string(self.struct_type_name)[0]
        assert self.struct_type is not None
        if self.is_stack_block:
            assert isinstance(self.insn, binja.HighLevelILVarDeclare)
            self.insn.var.name = f"stack_block_{self.insn.var.name}"
            self.insn.var.type = self.struct_type_name
            self.insn = shinobi.reload_hlil_instruction(self._bv, self.insn)
        else:
            self.data_var.name = f"global_block_{self.address:x}"
            self.data_var.type = self.struct_type_name

    def _type_for_ctype(self, ctype):
        if '!' in ctype:
            fallback = 'id'
            ctype = ctype.replace("!", "*")
        else:
            fallback = 'void *'
        try:
            return self._bv.parse_type_string(ctype)[0]
        except SyntaxError:
            return self._bv.parse_type_string(fallback)[0]

    def annotate_functions(self, bd):
        """
        Annotate the invoke function as well as the copy and dispose functions, if they exist.
        """
        invoke_func = self._bv.get_function_at(self.invoke)
        if bd.signature_raw is not None:
            ctypes = objctypes.ObjCEncodedTypes(bd.signature_raw).ctypes
            assert len(ctypes) > 0
            types = list(map(self._type_for_ctype, ctypes))
            types[1] = binja.Type.pointer(self._bv.arch, self.struct_type)
            invoke_func.type = binja.Type.function(types[0], types[1:])
        else:
            invoke_func.type = binja.Type.function(binja.Type.void(), [binja.Type.pointer(self._bv.arch, self.struct_type)], variable_arguments=True)
        if invoke_func.name == f"sub_{invoke_func.start:x}":
            invoke_func.name = f"sub_{invoke_func.start:x}_block_invoke"
        invoke_func.reanalyze()

        if bd.block_has_copy_dispose:
            copy_func = self._bv.get_function_at(bd.copy)
            copy_func.type = binja.Type.function(binja.Type.void(), [binja.Type.pointer(self._bv.arch, self.struct_type),
                                                                     binja.Type.pointer(self._bv.arch, self.struct_type)])
            if copy_func.name == f"sub_{copy_func.start:x}":
                copy_func.name = f"sub_{copy_func.start:x}_block_copy"
            dispose_func = self._bv.get_function_at(bd.dispose)
            dispose_func.type = binja.Type.function(binja.Type.void(), [binja.Type.pointer(self._bv.arch, self.struct_type)])
            if dispose_func.name == f"sub_{dispose_func.start:x}":
                dispose_func.name = f"sub_{dispose_func.start:x}_block_dispose"
            copy_func.reanalyze()
            dispose_func.reanalyze()


class BlockDescriptor:
    def __init__(self, bv, descriptor_address, block_flags):
        """
        Read block descriptor from data.
        """
        self._bv = bv
        self.address = descriptor_address
        self.block_flags = block_flags

        br = binja.BinaryReader(self._bv)
        br.seek(self.address)
        self.reserved = br.read64()
        self.size = br.read64()
        assert self.size >= 0x20
        if self.block_has_copy_dispose:
            self.copy = br.read64()
            self.dispose = br.read64()
        else:
            self.copy = None
            self.dispose = None
        if self.block_has_signature:
            self.signature = br.read64()
            if self.signature != 0:
                self.signature_raw = self._bv.get_ascii_string_at(self.signature, 0).raw
            else:
                self.signature_raw = None
            self.layout = br.read64()
            if self.layout != 0:
                if self.block_has_extended_layout:
                    if self.layout < 0x1000:
                        # compact encoding
                        self.n_strong_ptrs = (self.layout >> 8) & 0xf
                        self.n_byref_ptrs = (self.layout >> 4) & 0xf
                        self.n_weak_ptrs = self.layout & 0xf
                    else:
                        # XXX this is common with non-pointer types
                        raise NotImplementedError("BLOCK_HAS_EXTENDED_LAYOUT set but layout > 0x1000, layout bytecode not supported yet")
                else:
                    # XXX
                    raise NotImplementedError("BLOCK_HAS_EXTENDED_LAYOUT not set, legacy layout not supported yet")

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

    def __str__(self):
        return f"Block descriptor at {self.address:x} size {self.size:#x}"

    def annotate_descriptor(self, bl):
        """
        Annotate block descriptor.
        """
        struct = binja.StructureBuilder.create()
        struct.append(self._bv.parse_type_string("uint64_t reserved")[0], "reserved")
        struct.append(self._bv.parse_type_string("uint64_t size")[0], "size")
        if self.block_has_copy_dispose:
            struct.append(_get_libclosure_type(self._bv, "BlockCopyFunction"), "copy")
            struct.append(_get_libclosure_type(self._bv, "BlockDisposeFunction"), "dispose")
        if self.block_has_signature:
            struct.append(self._bv.parse_type_string("char const *signature")[0], "signature")
            if self.layout != 0:
                # should not reach this for non-extended layout
                assert self.block_has_extended_layout
                if self.layout < 0x1000:
                    struct.append(self._bv.parse_type_string("uint64_t layout")[0], "layout")
                else:
                    struct.append(self._bv.parse_type_string("uint8_t const *layout")[0], "layout")
            else:
                struct.append(self._bv.parse_type_string("void *layout")[0], "layout")
        self.struct_builder = struct
        self.struct_name = f"Block_descriptor_{self.address:x}"
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, self.struct_name), self.struct_name, self.struct_builder)
        self.struct_type_name = f"struct {self.struct_name}"
        self.struct_type = self._bv.parse_type_string(self.struct_type_name)[0]
        assert self.struct_type is not None
        data_var = self._bv.get_data_var_at(self.address)
        if data_var is None:
            self._bv.define_data_var(self.address, self.struct_type, f"block_descriptor_{self.address:x}")
        else:
            data_var.name = f"block_descriptor_{self.address:x}"
            data_var.type = self.struct_type

        # propagate struct type to descriptor pointer on block literal
        pointer_index = bl.struct_builder.index_by_name("descriptor")
        bl.struct_builder.replace(pointer_index, binja.Type.pointer(self._bv.arch, self.struct_type), "descriptor")
        self._bv.define_type(binja.Type.generate_auto_type_id(_TYPE_ID_SOURCE, bl.struct_name), bl.struct_name, bl.struct_builder)
        bl.struct_type = self._bv.parse_type_string(bl.struct_type_name)[0]


def annotate_global_block_literal(bv, block_literal_addr):
    where = f"global block {block_literal_addr:x}"

    print(f"Annotating {where}")

    block_literal_data_var = bv.get_data_var_at(block_literal_addr)
    if block_literal_data_var is None:
        # We only expect this to happen for manual invocation, not
        # for the automatic sweep, as the sweep requires data
        # references in order to pick up a global block instance.
        class_type = _get_objc_type(bv, "Class")
        bv.define_user_data_var(block_literal_addr, binja.Type.pointer(bv.arch, class_type))
        block_literal_data_var = bv.get_data_var_at(block_literal_addr)
        assert block_literal_data_var is not None

    data_var_value = block_literal_data_var.value
    if isinstance(data_var_value, dict) and 'isa' in data_var_value:
        data_var_value = data_var_value['isa']
    if not isinstance(data_var_value, int):
        print(f"{where}: Data var has value {data_var_value} of type {type(data_var_value).__name__}, expected int, fix plugin", file=sys.stderr)
        return
    ext_sym = shinobi.get_symbol_of_type(bv, "__NSConcreteGlobalBlock", binja.SymbolType.ExternalSymbol)
    if not data_var_value == ext_sym.address:
        print(f"{where}: Data var has value {data_var_value:x} instead of {ext_sym.address:x} __NSConcreteGlobalBlock", file=sys.stderr)
        return

    try:
        bl = BlockLiteral.from_data(bv, block_literal_data_var)
        print(bl)
        bd = BlockDescriptor(bv, bl.descriptor, bl.flags)
        print(bd)
        bl.annotate_literal(bd)
        bd.annotate_descriptor(bl)
        bl.annotate_functions(bd)
    except NotImplementedError as e:
        print(f"{where}: {e}", file=sys.stderr)
        return


def annotate_stack_block_literal(bv, block_literal_insn):
    where = f"stack block {block_literal_insn.address:x}"

    print(f"Annotating {where}")

    # XXX also check for __NSConcreteStackBlock here in case we got here via manual command
    if not (isinstance(block_literal_insn, binja.HighLevelILVarInit) and \
            (block_literal_insn.dest.source_type == binja.VariableSourceType.StackVariableSourceType)):
        print(f"{where}: Instruction is not a stack variable initialization", file=sys.stderr)
        return

    try:
        bl = BlockLiteral.from_stack(bv, block_literal_insn)
        print(bl)
        bd = BlockDescriptor(bv, bl.descriptor, bl.flags)
        print(bd)
        bl.annotate_literal(bd)
        bd.annotate_descriptor(bl)
        bl.annotate_functions(bd)
    except NotImplementedError as e:
        print(f"{where}: {e}", file=sys.stderr)
        return

    # annotate stack byrefs

    if bd.imported_variables_size > 0:
        assert bd.layout != 0
        if bd.layout < 0x1000 and bd.n_byref_ptrs > 0:
            byref_srcs = []
            try:
                for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(bl.insn.function, bl.insn.var.identifier):
                    if isinstance(insn.src, binja.HighLevelILVar):
                        insn_src = insn.src
                    elif isinstance(insn.src, binja.HighLevelILAddressOf):
                        insn_src = insn.src
                    elif isinstance(insn.src, (binja.HighLevelILDerefField,
                                               binja.HighLevelILDeref,
                                               binja.HighLevelILImport,
                                               binja.HighLevelILConst,
                                               binja.HighLevelILConstPtr)):
                        insn_src = None
                    else:
                        print(f"{where}: Skipping assignment right-hand-side for {insn.src!r}, fix plugin", file=sys.stderr)
                        continue
                    if insn.dest.member_index >= 5 + bd.n_strong_ptrs and insn.dest.member_index < 5 + bd.n_strong_ptrs + bd.n_byref_ptrs:
                        byref_srcs.append(insn_src)
            except NotImplementedError as e:
                print(f"{where}: {e}", file=sys.stderr)

            assert bd.n_byref_ptrs == len(byref_srcs)
            for byref_src in byref_srcs:
                if byref_src is None:
                    continue
                if isinstance(byref_src.src, binja.HighLevelILVar):
                    var_id = byref_src.src.var.identifier
                elif isinstance(byref_src.src, binja.HighLevelILAdd):
                    print(f"{where}: Byref src var {byref_src} src is HighLevelILAdd: Annotate manually", file=sys.stderr)
                    continue
                else:
                    print(f"{where}: Byref src var {byref_src} src is {type(byref_src.src).__name__}: Annotate manually", file=sys.stderr)
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
                    print(f"{where}: Byref src var {byref_src} id {var_id:x} not found in function's var declarations and inits", file=sys.stderr)
                    continue

                # So apparently this works; despite the reloads, byref_srcs are not invalidated, identifiers are still current.
                # Should that cease to be the case, we'll need to find next byref_src in a way that is robust to reloads.

                byref_insn_var.name = f"block_byref_{byref_insn_var.name}"

                byref_struct = binja.StructureBuilder.create()
                byref_struct.append(_get_objc_type(bv, "Class"), "isa")
                byref_struct.append(bv.parse_type_string("void *forwarding")[0], "forwarding") # placeholder
                byref_struct.append(bv.parse_type_string("volatile int32_t flags")[0], "flags")
                byref_struct.append(bv.parse_type_string("uint32_t size")[0], "size")

                byref_insn_var.type = byref_struct
                byref_insn = shinobi.reload_hlil_instruction(bv, byref_insn)
                byref_insn_var = byref_insn.var

                for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(byref_insn.function, byref_insn_var.identifier):
                    # 0 isa
                    # 1 forwarding
                    if insn.dest.member_index == 2:
                        assert isinstance(insn.src, binja.HighLevelILConst)
                        byref_flags = insn.src.constant
                    elif insn.dest.member_index == 3:
                        assert isinstance(insn.src, binja.HighLevelILConst)
                        byref_size = insn.src.constant

                if (byref_flags & BLOCK_BYREF_HAS_COPY_DISPOSE) != 0:
                    byref_struct.append(_get_libclosure_type(bv, "BlockByrefKeepFunction"), "byref_keep")
                    byref_struct.append(_get_libclosure_type(bv, "BlockByrefDestroyFunction"), "byref_destroy")
                byref_layout_nibble = (byref_flags & BLOCK_BYREF_LAYOUT_MASK)
                if byref_layout_nibble == BLOCK_BYREF_LAYOUT_EXTENDED:
                    byref_struct.append(bv.parse_type_string("void *layout")[0], "layout")
                    layout_index = byref_struct.index_by_name("layout")
                    byref_insn_var.type = byref_struct
                    byref_insn = shinobi.reload_hlil_instruction(bv, byref_insn)
                    byref_insn_var = byref_insn.var
                    for insn in shinobi.yield_struct_field_assign_hlil_instructions_for_var_id(byref_insn.function, byref_insn_var.identifier):
                        if insn.dest.member_index == layout_index:
                            isinstance(insn.src, binja.HighLevelILConstPtr)
                            byref_layout = insn.src.constant
                            break
                    if byref_layout != 0:
                        if byref_layout < 0x1000:
                            byref_struct.replace(layout_index, bv.parse_type_string("uint64_t layout")[0], "layout")
                            # compact encoding
                            n_strong_ptrs = (byref_layout >> 8) & 0xf
                            n_byref_ptrs = (byref_layout >> 4) & 0xf
                            n_weak_ptrs = byref_layout & 0xf
                            for i in range(n_strong_ptrs):
                                struct.append(_get_objc_type(bv, "id"), f"strong_ptr_{i}")
                            for i in range(n_byref_ptrs):
                                struct.append(_get_objc_type(bv, "id"), f"byref_ptr_{i}")
                            for i in range(n_weak_ptrs):
                                struct.append(_get_objc_type(bv, "id"), f"weak_ptr_{i}")
                        else:
                            byref_struct.replace(layout_index, bv.parse_type_string("uint8_t const *layout")[0], "layout")
                            # XXX append fields according to layout
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_NON_OBJECT:
                    byref_struct.append(bv.parse_type_string("uint64_t non_object_0")[0], "non_object_0")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_STRONG:
                    byref_struct.append(_get_objc_type(bv, "id"), "strong_ptr_0")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_WEAK:
                    byref_struct.append(_get_objc_type(bv, "id"), "weak_ptr_0")
                elif byref_layout_nibble == BLOCK_BYREF_LAYOUT_UNRETAINED:
                    byref_struct.append(_get_objc_type(bv, "id"), "unretained_ptr_0")

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

                # XXX propagate byref type to block literal type (need byref's block literal struct member index)

                # XXX annotate functions (hard with use of temporary 128-bit reg)

    return


def annotate_all_global_blocks(bv, set_progress=None):
    ext_sym = shinobi.get_symbol_of_type(bv, "__NSConcreteGlobalBlock", binja.SymbolType.ExternalSymbol)
    assert ext_sym is not None and ext_sym.address is not None and ext_sym.address != 0
    for addr in bv.get_data_refs(ext_sym.address):
        if set_progress is not None:
            set_progress(f"{addr:x}")
        annotate_global_block_literal(bv, addr)


def annotate_all_stack_blocks(bv, set_progress=None):
    imp_data_sym = shinobi.get_symbol_of_type(bv, "__NSConcreteStackBlock", binja.SymbolType.ImportedDataSymbol)
    # We'd want to use get_code_refs here, but it is very unreliable.
    # Yielded refsrc objects often have only llil but not mlil or hlil;
    # .llil.hlil is also None, .llil.hlils contains the llil that matches,
    # sometimes multiple times.  The issue seems more frequent on but not
    # limited to arm64.
    #for refsrc in bv.get_code_refs(imp_data_sym.address):
    #    print(refsrc)
    #    print(refsrc.llil, refsrc.mlil, refsrc.hlil, refsrc.llil.hlil, refsrc.llil.hlils)
    for insn in bv.hlil_instructions:
        if not isinstance(insn, binja.HighLevelILVarInit):
            continue
        if not isinstance(insn.src, binja.HighLevelILImport):
            continue
        if insn.src.constant != imp_data_sym.address:
            continue
        if set_progress is not None:
            set_progress(f"{insn.address:x}")
        annotate_stack_block_literal(bv, insn)


@shinobi.register_for_high_level_il_instruction("Blocks\\Stack block here", is_valid=is_valid)
@shinobi.background_task("Blocks: Stack block")
def plugin_cmd_stack_block_literal_here(bv, block_literal_insn, set_progress=None):
    """
    Define a stack block literal here.
    """
    annotate_stack_block_literal(bv, block_literal_insn)


@shinobi.register_for_address("Blocks\\Global block here", is_valid=is_valid)
@shinobi.background_task("Blocks: Global block")
def plugin_cmd_global_block_literal_here(bv, address, set_progress=None):
    """
    Define a global block literal here.
    """
    annotate_global_block_literal(bv, address)


@shinobi.register("Blocks\\Annotate all stack blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All stack blocks")
def plugin_cmd_annotate_all_stack_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteStackBlock and
    annotate stack blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_stack_blocks(bv, set_progress=set_progress)


@shinobi.register("Blocks\\Annotate all global blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All global blocks")
def plugin_cmd_annotate_all_global_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteGlobalBlock and
    annotate stack blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_global_blocks(bv, set_progress=set_progress)


@shinobi.register("Blocks\\Annotate all blocks", is_valid=is_valid)
@shinobi.background_task("Blocks: All blocks")
def plugin_cmd_annotate_all_stack_blocks(bv, set_progress=None):
    """
    Look for all occurences of __NSConcreteGlobalBlock and __NSConcreteStackBlock
    and annotate all blocks where references are found.
    """
    _define_ns_concrete_block_imports(bv)
    annotate_all_global_blocks(bv, set_progress=set_progress)
    annotate_all_stack_blocks(bv, set_progress=set_progress)
