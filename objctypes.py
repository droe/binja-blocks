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
    t   int128_t (undocumented)
    T   uint128_t (undocumented)
    f   float
    d   double
    D   long double (undocumented)
    B   bool (C++/C)
    v   void
    *   char *
    @   ObjC object of format:  @ [ "classname" ]
    #   ObjC class object
    :   ObjC method selector
    ?   unknown type, also used for function pointers
    ' ' not implemented by LLVM (undocumented)

    Special types:
    b   bitfield of format:     b num_bits
    @?  block pointer (undocumented)
        optionally followed by full block signature
        < ret-val-type @? param-type ... >

    Nested types:
    []  array of format:        [ num_elements type ]
    {}  structure of format:    { name = type ... }
    ()  union of format:        ( name = type ... )
    ^   pointer of format:      ^ target_type

    Type qualifiers:
    r   const (read-only)
    n   in
    N   inout
    o   out
    O   bycopy
    R   byref
    V   oneway

    Property encodings:
    R   read-only
    C   by-copy
    &   by-reference
    D   dynamic
    G   getter                  G selector
    S   setter                  S selector
    V   instance variable       V var name
    T   type encoding           T old-style type encoding
    W   weak
    P   strong
    N   non-atomic

    Structure (this is pure guesswork):
    signature = type_and_stack_size [ ... ]
    type_and_stack_size = type stack_size
    type = [ qualifier ] { basic_type | nested_type } [ bitfield ... ]
    stack_size = number [ ... ]

    Caveats:
    Block pointer encoding is undocumented but well-known.
    Qualifier positioning and semantics is guesswork.
    Qualifiers other than const (r) are ignored.
    Not sure how to disambiguate bitfield width from stack size.
    Bitfields are ignored.

    Notable hacks:
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
    ['void', 'void *', 'NSString !', 'struct _NSRange', 'struct _NSRange', 'bool *']
    >>> ObjCEncodedTypes(b'v24@?0{shared_ptr<CLConnectionMessage>=^{CLConnectionMessage}^{__shared_weak_count}}8').ctypes
    ['void', 'void *', 'void *']
    >>> ObjCEncodedTypes(b'r^{__CFString=}8@?0').ctypes
    ['const struct __CFString *', 'void *']
    >>> ObjCEncodedTypes(b'{PersistentSubscriptionIdentifier={basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{type_index=^{type_info}}}8@?0').ctypes
    ['struct PersistentSubscriptionIdentifier', 'void *']
    >>> ObjCEncodedTypes(b'{CLWifiLocationUpdateRequest=iiB{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}diBBiidddddiBBBi{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}}8@?0').ctypes
    ['struct CLWifiLocationUpdateRequest', 'void *']
    >>> ObjCEncodedTypes(b'{Fence={basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}ddddddddiiidQiiBiiB{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{CLStrongPtr<NSUUID *>=@}{vector<CLClientLocationCoordinate, std::allocator<CLClientLocationCoordinate>>=^{?}^{?}{__compressed_pair<CLClientLocationCoordinate *, std::allocator<CLClientLocationCoordinate>>=^{?}}}}8@?0').ctypes
    ['struct Fence', 'void *']
    >>> ObjCEncodedTypes(b'{ScanParameters=iii{vector<int, std::allocator<int>>=^i^i{__compressed_pair<int *, std::allocator<int>>=^i}}{duration<long long, std::ratio<1, 1000>>=q}{duration<long long, std::ratio<1>>=q}BB{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}c}8@?0').ctypes
    ['struct ScanParameters', 'void *']
    >>> ObjCEncodedTypes(b'{MonitoredRegion=^^?{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}SSi{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}i}8@?0').ctypes
    ['struct MonitoredRegion', 'void *']
    >>> ObjCEncodedTypes(b'{Name={basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}BBB{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}{basic_string<char, std::char_traits<char>, std::allocator<char>>={__compressed_pair<std::basic_string<char>::__rep, std::allocator<char>>={__rep=(?={__long=*Qb63b1}{__short=[23c][0C]b7b1}{__raw=[3Q]})}}}BBB}8@?0').ctypes
    ['struct Name', 'void *']
    >>> ObjCEncodedTypes(b'v20@?0B8@?<{CLDaemonLocation=i{?=dd}ddddddddidi{?=dd}diIiiidB}@?>12').ctypes
    ['void', 'void *', 'bool', 'void *']
    >>> ObjCEncodedTypes(b'v16@?0@?<{vector<CLFenceManager_Type::Fence, std::allocator<CLFenceManager_Type::Fence>>=^{Fence}^{Fence}{__compressed_pair<CLFenceManager_Type::Fence *, std::allocator<CLFenceManager_Type::Fence>>=^{Fence}}}@?>8').ctypes
    ['void', 'void *', 'void *']
    >>> ObjCEncodedTypes(b'v24@?0{time_point<cl::chrono::CFAbsoluteTimeClock, std::chrono::duration<long double>>={duration<long double, std::ratio<1>>=D}}8r^v16').ctypes
    ['void', 'void *', 'struct time_point<cl::chrono::CFAbsoluteTimeClock, std::chrono::duration<long double>>', 'const void *']
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
        b"t": "int128_t",
        b"T": "uint128_t",
        b"f": "float",
        b"d": "double",
        b"D": "long double",
        b"B": "bool",
        b"v": "void",
        b"*": "char *",
        b"#": "Class",
        b":": "SEL",
        b"?": "void *",
        b" ": "void",
    }

    def __init__(self, raw):
        self._raw = raw
        self._idx = 0
        if len(raw) > 0:
            self._end = len(raw)
            self.ctypes = self._parse_signature()
            assert self._idx == self._end
        else:
            self.ctypes = []

    def _peek(self, n=1):
        if self._idx + n <= self._end:
            return self._raw[self._idx:self._idx + n]
        return None

    def _consume(self, n=1):
        self._idx += n
        assert self._idx <= self._end

    def _parse_signature(self):
        #print(f"_parse_signature idx {self._idx} {self._raw[self._idx:]}", file=sys.stderr)
        ctypes = []
        while self._idx < self._end:
            if self._peek() == b">":
                break
            t = self._parse_type()
            self._parse_number()
            ctypes.append(t)
        return ctypes

    def _skip_bitfield(self):
        c = self._peek()
        while c == b"b":
            self._consume(1)
            _ = self._parse_number()
            c = self._peek()

    def _parse_type(self):
        #print(f"_parse_type idx {self._idx} {self._raw[self._idx:]}", file=sys.stderr)
        c = self._peek()

        # qualifiers
        quals = []
        if c == b"r":
            quals.append("const")
            self._consume(1)
            c = self._peek()
        elif c in [b"n", b"N", b"o", b"O", b"R", b"V"]:
            self._consume(1)
            c = self._peek()
        if len(quals) > 0:
            quals.append("")
        qual = " ".join(quals)

        if c == b"@":
            cc = self._peek(2)
            if cc == b"@?":
                self._consume(2)
                if self._peek() == b"<":
                    self._consume(1)
                    _ = self._parse_signature()
                    assert self._peek() == b">"
                    self._consume(1)
                return qual + "void *"
            elif cc == b"@\"":
                self._consume(2)
                classname = self._parse_classname()
                assert self._peek() == b"\""
                self._consume(1)
                if classname[:1] == b"<":
                    return qual + f"NSObject{classname} !"
                else:
                    return qual + f"{classname} !"
            else:
                self._consume(1)
                return qual + "id"

        ctype = self.BASIC_TYPE_MAP.get(c, None)
        if ctype is not None:
            self._consume(1)
            self._skip_bitfield()
            return qual + ctype

        if c == b"^":
            self._consume(1)
            target_ctype = self._parse_type()
            self._skip_bitfield()
            if target_ctype[-1:] == "*":
                return qual + target_ctype + "*"
            else:
                return qual + target_ctype + " *"

        if c in b"{(":
            if c == b"{":
                sentinel = b"}"
            else:
                sentinel = b")"
            self._consume(1)
            structname = self._parse_structname(sentinel)
            c = self._peek()
            assert c in [b"=", sentinel]
            if c == b"=":
                # has type info
                self._consume(1)
                member_types = []
                while (c := self._peek()) is not None and c != sentinel:
                    t = self._parse_type()
                    member_types.append(t)
            elif c == sentinel:
                # no type info
                pass
            assert self._peek() == sentinel
            self._consume(1)
            self._skip_bitfield()
            # We could try to construct an anonymous struct or
            # union here, but let's not bother for now.
            if any([structname.startswith(prefix) for prefix in ["shared_ptr<", "unique_ptr<", "weak_ptr<"]]):
                # C++ smart pointers
                return qual + "void *"
            if sentinel == b"}":
                return qual + f"struct {structname}"
            else:
                return qual + f"union {structname}"

        if c in b"[":
            self._consume(1)
            n = self._parse_number()
            t = self._parse_type()
            assert self._peek() == b"]"
            self._consume(1)
            self._skip_bitfield()
            return qual + f"{t}[{n}]"

        raise NotImplementedError(f"unsupported type '{c}'")

    _DIGITS = set([b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"])

    def _parse_number(self):
        start = self._idx
        end = start
        while (c := self._peek()) is not None and c in self._DIGITS:
            self._consume(1)
            end += 1
        return self._raw[start:end].decode()

    def _parse_terminated_string(self, sentinels):
        start = self._idx
        end = start
        while (c := self._peek()) is not None and c not in sentinels:
            self._consume(1)
            end += 1
        return self._raw[start:end].decode()

    def _parse_classname(self):
        return self._parse_terminated_string([b"\""])

    def _parse_structname(self, sentinel):
        return self._parse_terminated_string([b"=", sentinel])


def _test():
    import doctest
    fails, tests = doctest.testmod(optionflags=doctest.IGNORE_EXCEPTION_DETAIL)
    sys.exit(min(1, fails))


if __name__ == '__main__':
    if '--test' in sys.argv:
        _test()
