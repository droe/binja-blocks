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


import sys


class ObjCEncodedTypes:
    """
    Basic types:
    c   char
    i   int
    s   short
    l   long
    q   long long
    C   unsigned char
    I   unsigned int
    S   unsigned short
    L   unsigned long
    Q   unsigned long long
    f   float
    d   double
    B   bool (C++/C)
    v   void
    *   char *
    @   ObjC object of format:  @ [ "classname" ]
    #   ObjC class object
    :   ObjC method selector
    ?   unknown type, also used for function pointers

    Special types:
    @?  block pointer
    b   bitfield of format:     b num_bits

    Nested types:
    []  array of format:        [ num_elements type ]
    {}  structure of format:    { name = type ... }
    ()  union of format:        ( name = type ... )
    ^   pointer of format:      ^ target_type

    Type qualifiers:
    r   const
    n   in
    N   inout
    o   out
    O   bycopy
    R   byref
    V   oneway

    Structure:
    signature = type_and_stack_size [ ... ]
    type_and_stack_size = type [ qualifier ] stack_size
    type = { basic_type | nested_type }
    stack_size = number [ ... ]

    Caveats:
    Block pointer encoding is undocumented but well-known.
    Qualifier positioning is a guess, haven't seen this in block types.
    Not sure how to disambiguate bitfield width from stack size.

    Not imeplemnted:
    Bitfields, type qualifiers

    Hacks:
    For types that need fallback to id instead of void *, ! is emitted.
    This is useful for emitting more specific types where possible, but
    having a correct fallback where not, e.g. because Binja does not
    know about a class or protocol.

    >>> ObjCEncodedTypes(b"v8@?0").ctypes
    ['void', 'void *']
    >>> ObjCEncodedTypes(b"v32@?0@8@16^B24").ctypes
    ['void', 'void *', 'id', 'id', 'bool *']
    >>> ObjCEncodedTypes(b"[12^f]").ctypes
    ['float *[12]']
    >>> ObjCEncodedTypes(b'v32@?0@"NSURL"8@"NSURLResponse"16@"NSError"24').ctypes
    ['void', 'void *', 'NSURL !', 'NSURLResponse !', 'NSError !']
    >>> ObjCEncodedTypes(b'v32@?0@"<SomeProtocol>"8Q16^B24').ctypes
    ['void', 'void *', '<SomeProtocol> !', 'unsigned long long', 'bool *']
    >>> ObjCEncodedTypes(b'v56@?0@"NSString"8{_NSRange=QQ}16{_NSRange=QQ}32^B48').ctypes
    ['void', 'void *', 'NSString !', 'void *', 'void *', 'bool *']
    """

    BASIC_TYPE_MAP = {
        b"c": "char",
        b"i": "int",
        b"s": "short",
        b"l": "long",
        b"q": "long long",
        b"C": "unsigned char",
        b"I": "unsigned int",
        b"S": "unsigned short",
        b"L": "unsigned long",
        b"Q": "unsigned long long",
        b"f": "float",
        b"d": "double",
        b"B": "bool",
        b"v": "void",
        b"*": "char *",
        b"#": "Class",
        b":": "SEL",
        b"?": "void *",
    }

    def __init__(self, raw):
        self._raw = raw
        self._idx = 0
        self.ctypes = []
        if len(raw) > 0:
            self._end = len(raw)
            self._parse()

    def _peek(self, n=1):
        if self._idx + n <= self._end:
            return self._raw[self._idx:self._idx + n]
        return None

    def _consume(self, n=1):
        self._idx += n
        assert self._idx <= self._end

    def _parse(self):
        while self._idx < self._end:
            t = self._parse_type_code()
            self._parse_number()
            self.ctypes.append(t)

    def _parse_type_code(self):
        c = self._peek()

        if c == b"@":
            cc = self._peek(2)
            if cc == b"@?":
                self._consume(2)
                return "void *"
            elif cc == b"@\"":
                self._consume(2)
                classname = self._parse_classname()
                assert self._peek() == b"\""
                self._consume(1)
                if classname[:1] == b"<":
                    return f"NSObject{classname} !"
                else:
                    return f"{classname} !"
            else:
                self._consume(1)
                return "id"

        ctype = self.BASIC_TYPE_MAP.get(c, None)
        if ctype is not None:
            self._consume(1)
            return ctype

        if c == b"^":
            self._consume(1)
            target_ctype = self._parse_type_code()
            if target_ctype[-1:] == "*":
                return target_ctype + "*"
            else:
                return target_ctype + " *"

        if c in b"{(":
            if c == b"{":
                sentinel = b"}"
            else:
                sentinel = b")"
            self._consume(1)
            structname = self._parse_structname()
            assert self._peek() == b"="
            self._consume(1)
            member_types = []
            while (c := self._peek()) is not None and c != sentinel:
                t = self._parse_type_code()
                member_types.append(t)
            assert self._peek() == sentinel
            self._consume(1)
            # We could try to construct an anonymous struct or
            # union here, but let's not bother for now.
            return "void *"

        if c in b"[":
            self._consume(1)
            n = self._parse_number()
            t = self._parse_type_code()
            assert self._peek() == b"]"
            self._consume(1)
            return f"{t}[{n}]"

        raise NotImplementedError(f"unsupported type '{c}'")

    _DIGITS = set([b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"])

    def _parse_number(self):
        start = self._idx
        end = start
        while (c := self._peek()) is not None and c in self._DIGITS:
            self._consume(1)
            end += 1
        return self._raw[start:end].decode()

    def _parse_terminated_string(self, sentinel):
        start = self._idx
        end = start
        while (c := self._peek()) is not None and c != sentinel:
            self._consume(1)
            end += 1
        return self._raw[start:end].decode()

    def _parse_classname(self):
        return self._parse_terminated_string(b"\"")

    def _parse_structname(self):
        return self._parse_terminated_string(b"=")


def _test():
    import doctest
    fails, tests = doctest.testmod(optionflags=doctest.IGNORE_EXCEPTION_DETAIL)
    sys.exit(min(1, fails))


if __name__ == '__main__':
    if '--test' in sys.argv:
        _test()
