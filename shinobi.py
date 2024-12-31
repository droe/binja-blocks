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


#
# Plugin command decorators
#


def register(label, *args, **kvargs):
    """
    Decorator to register the decorated function as a general plugin command.
    """
    def decorator(func):
        binja.PluginCommand.register(label, func.__doc__, func, *args, **kvargs)
        return func
    return decorator


def register_for_function(label, *args, **kvargs):
    """
    Decorator to register the decorated function as a function plugin command.
    """
    def decorator(func):
        binja.PluginCommand.register_for_function(label, func.__doc__, func, *args, **kvargs)
        return func
    return decorator


def register_for_address(label, *args, **kvargs):
    """
    Decorator to register the decorated function as an address plugin command.
    """
    def decorator(func):
        binja.PluginCommand.register_for_address(label, func.__doc__, func, *args, **kvargs)
        return func
    return decorator


def register_for_high_level_il_instruction(label, *args, **kvargs):
    """
    Decorator to register the decorated function as a HLIL instruction plugin command.
    """
    def decorator(func):
        binja.PluginCommand.register_for_high_level_il_instruction(label, func.__doc__, func, *args, **kvargs)
        return func
    return decorator


class Task(binja.plugin.BackgroundTaskThread):
    """
    Helper class to run an analysis on a background thread.
    Only one task can be running at a given time; additional
    tasks are queued until the running task has finished.
    """

    class Cancelled(Exception):
        pass

    __running = None
    __waiting = []

    def __init__(self, label, func, *args, **kvargs):
        if "can_cancel" in kvargs:
            self.__can_cancel = kvargs["can_cancel"]
            del kvargs["can_cancel"]
        else:
            self.__can_cancel = False
        super().__init__(label, self.__can_cancel)
        self.__label = label
        self.__func = func
        self.__args = args
        self.__kvargs = kvargs

    def set_progress(self, text):
        self.progress = f"{self.__label}...{text}"
        if self.__can_cancel and self.cancelled:
            raise Task.Cancelled()

    def run(self):
        self.__func(*self.__args, **(self.__kvargs | {'set_progress': self.set_progress}))
        self.finish()
        assert Task.__running == self
        if len(Task.__waiting) > 0:
            Task.__running = Task._waiting.pop(0)
            Task.__running.start()
        else:
            Task.__running = None

    @classmethod
    def spawn(cls, label, func, *args, **kvargs):
        task = cls(label, func, *args, **kvargs)
        if Task.__running is not None:
            Task.__waiting.append(task)
        else:
            Task.__running = task
            Task.__running.start()


def background_task(label="Plugin action", can_cancel=True):
    """
    Decorator for plugin command functions to run them on a
    background thread using Task.
    This is useful, because some of Binary Ninja's APIs refuse
    to work on the main thread or on a UI thread.
    Unfortunately, despite running on a background thread,
    there is still a lot of beach-balling going on in the UI.
    But at least all the APIs can be used.
    """
    def decorator(func):
        def closure(*args, **kvargs):
            Task.spawn(label, func, *args, can_cancel=can_cancel, **kvargs)
        closure.__doc__ = func.__doc__
        return closure
    return decorator


def undoable(func):
    """
    Decorator for plugin command functions to make them undoable.
    """
    def closure(bv, *args, **kvargs):
        state = bv.begin_undo_actions()
        try:
            func(bv, *args, **kvargs)
        finally:
            bv.commit_undo_actions(state)
    closure.__doc__ = func.__doc__
    return closure


#
# StructureBuilder extensions
#


def _append_with_offset_suffix(self, type_, name):
    """
    Append a field with type and name to the StructureBuilder,
    and append the offset of the field to the name.
    Monkey-patching this in to avoid a lot of duplicate code.
    """
    self.append(type_, name)
    self.replace(len(self.members) - 1,
                 self.members[-1].type,
                 f"{self.members[-1].name}{self.members[-1].offset:x}")
    return self
binja.StructureBuilder.append_with_offset_suffix = _append_with_offset_suffix


#
# BinaryView extensions
#


def _yield_symbols_of_type(self, name, type_):
    """
    Find all symbols of a specific type and return a generator for them.
    """
    for sym in filter(lambda x: x.type == type_, self.symbols.get(name, [])):
        yield sym
binja.BinaryView.x_yield_symbols_of_type = _yield_symbols_of_type


def _get_symbol_of_type(self, name, type_):
    """
    Find a symbol of a specific type and return the first one found.
    """
    try:
        return next(self.x_yield_symbols_of_type(name, type_))
    except StopIteration:
        return None
binja.BinaryView.x_get_symbol_of_type = _get_symbol_of_type


def _get_symbol_addresses_set(self, name):
    """
    Find all symbols of a name and return a set of all their addresses.
    """
    syms = self.symbols.get(name, [])
    syms = filter(lambda sym: sym.address is not None and sym.address != 0, syms)
    return set([sym.address for sym in syms])
binja.BinaryView.x_get_symbol_addresses_set = _get_symbol_addresses_set


def _parse_type(self, type_str):
    """
    Like parse_type_string, but returns only the type and discards
    the name.  Typical use is to only pass a type without a name
    in type_str.
    """
    return self.parse_type_string(type_str)[0]
binja.BinaryView.x_parse_type = _parse_type


def _make_data_var(self, address, type_, name=None):
    """
    Make a data var of given type and name at address.
    If a data var already exists, its name and type are set.
    If a data var does not exist, it is created.
    """
    data_var = self.get_data_var_at(address)
    if data_var is None:
        if name is not None:
            self.define_data_var(address, type_, name)
        else:
            self.define_data_var(address, type_)
    else:
        if name is not None:
            data_var.name = name
        data_var.type = type_
binja.BinaryView.x_make_data_var = _make_data_var


def _reload_hlil_instruction(self, hlil_insn, predicate=None):
    """
    Refresh the instruction and the function it is associated with.
    This is useful after setting the type of an operand in situations
    where there is a need to examine the instruction and function
    after applying the new type.
    If no predicate is given, return the first instruction at the
    same address.  If a predicate is given, return the first
    instruction at the same address that matches the predicate.
    """
    reloaded_func = self.get_function_at(hlil_insn.function.source_function.start)
    for insn in reloaded_func.hlil.instructions:
        if insn.address == hlil_insn.address:
            if predicate is not None and not predicate(insn):
                continue
            reloaded_insn = insn
            break
    else:
        reloaded_insn = None
    assert reloaded_insn is not None
    return reloaded_insn
binja.BinaryView.x_reload_hlil_instruction = _reload_hlil_instruction


def _get_byte_string_at(self, addr, min_len=0):
    """
    Read a NUL-terminated byte string from address.
    Returns bytes including the terminating NUL.
    The first min_len bytes can contain
    non-terminating NUL characters.
    Does not attempt to decode the string and will
    happily read invalid UTF-8.
    Does not create a StringReference.
    Does not annotate anything.
    """
    br = binja.BinaryReader(self)
    br.seek(addr)
    octets = []
    while len(octets) < min_len:
        octets.append(br.read8())
    while len(octets) == 0 or octets[-1] != 0:
        octets.append(br.read8())
    if any([c is None for c in octets]):
        return None
    return bytes(octets)
binja.BinaryView.x_get_byte_string_at = _get_byte_string_at


#
# Other helpers
#


def yield_struct_field_assign_hlil_instructions_for_var_id(hlil_func, var_id):
    """
    Find all HLIL instructions that assign to struct fields of
    a struct with a given variable identifier.

    Note that variable identifiers may change across type changes
    in the function.
    """
    for insn in hlil_func.instructions:
        if not isinstance(insn, binja.HighLevelILAssign):
            continue
        if not isinstance(insn.dest, binja.HighLevelILStructField):
            continue

        if isinstance(insn.dest.src, binja.HighLevelILVar):
            stack_var = insn.dest.src.var
        elif isinstance(insn.dest.src, binja.HighLevelILArrayIndex):
            if not isinstance(insn.dest.src.src, binja.HighLevelILVar):
                continue
            stack_var = insn.dest.src.src.var
        elif isinstance(insn.dest.src, binja.HighLevelILStructField):
            if not isinstance(insn.dest.src.src, binja.HighLevelILVar):
                continue
            stack_var = insn.dest.src.src.var
        elif isinstance(insn.dest.src, binja.HighLevelILDerefField):
            continue
        else:
            raise NotImplementedError(f"Unhandled destination source type {type(insn.dest.src).__name__} in assign insn {insn!r}, fix plugin")

        if stack_var.identifier != var_id:
            continue

        yield insn
