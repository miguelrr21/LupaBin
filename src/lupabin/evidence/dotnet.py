"""The metadata of a .NET assembly (ECMA-335, partition II), read without running it.

Method `ecma335-metadata-v1`. Only the optimized layout is read: one `#~` stream, no
pointer tables, the 45 tables of the standard. Anything else (the unoptimized `#-`
stream, duplicated streams, extra header data, tables above GenericParamConstraint and
MethodSpec) is left unread rather than guessed: obfuscators produce those forms and the
runtime resolves them in ways the standard does not fix.

The worker and the host run the same derivation (`read`), so the host accepts a fact
only if it derives it again from the sample's bytes. Everything here is bounded: no
recursion, no loop longer than the rows it publishes, and every failure is a ValueError.

A row that is published names what the assembly declares or refers to. It says nothing
of which code runs: the IL of the methods is not read.
"""

import struct
from typing import NamedTuple

METHOD = "ecma335-metadata-v1"
CLR_DIRECTORY = 14
CLI_SIZE = 72
ROOT = b"BSJB"
VERSION_MAX = 256
STREAMS_MAX = 16
STREAM_NAME_MAX = 32
NAME_MAX = 512  # bytes of a name in #Strings that is published
ROWS_MAX = 0xFFFFFF  # a metadata token has 24 bits for the row
SCOPE_DEPTH = 8  # nested types followed to reach the assembly that declares them
SECTIONS_MAX = 96
ASSEMBLY_REFS = 128
PINVOKES = 1024
MEMBERS = 4096
TYPES = 1024
USER_STRINGS = 2048
USER_STEPS = 262144  # length prefixes of #US examined, empty entries included
USER_CHARACTERS = 4  # the shortest literal published, as for the strings of the file

MODULE, TYPE_REF, TYPE_DEF, FIELD, METHOD_DEF, PARAM = 0, 1, 2, 4, 6, 8
MEMBER_REF, MODULE_REF, TYPE_SPEC, IMPL_MAP = 10, 26, 27, 28
ASSEMBLY, ASSEMBLY_REF = 32, 35
TABLES = 45
POINTER_TABLES = (3, 5, 7, 19, 22)

# Coded indexes (II.24.2.6): the tables a tag selects; None is a tag the standard
# leaves unused.
CODED: dict[str, tuple[int | None, ...]] = {
    "TypeDefOrRef": (2, 1, 27),
    "HasConstant": (4, 8, 23),
    "HasCustomAttribute": (
        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
    ),
    "HasFieldMarshal": (4, 8),
    "HasDeclSecurity": (2, 6, 32),
    "MemberRefParent": (2, 1, 26, 6, 27),
    "HasSemantics": (20, 23),
    "MethodDefOrRef": (6, 10),
    "MemberForwarded": (4, 6),
    "Implementation": (38, 35, 39),
    "CustomAttributeType": (None, None, 6, 10, None),
    "ResolutionScope": (0, 26, 35, 1),
    "TypeOrMethodDef": (2, 6),
}  # fmt: skip

# Columns of each table (II.22): 2 and 4 are fixed widths, S, G and B index the #Strings,
# #GUID and #Blob heaps, an integer names a table and a string a coded index.
Column = int | str
SCHEMA: tuple[tuple[Column, ...], ...] = (
    ("w2", "S", "G", "G", "G"),  # 0 Module
    ("ResolutionScope", "S", "S"),  # 1 TypeRef
    ("w4", "S", "S", "TypeDefOrRef", 4, 6),  # 2 TypeDef
    (4,),  # 3 FieldPtr
    ("w2", "S", "B"),  # 4 Field
    (6,),  # 5 MethodPtr
    ("w4", "w2", "w2", "S", "B", 8),  # 6 MethodDef
    (8,),  # 7 ParamPtr
    ("w2", "w2", "S"),  # 8 Param
    (2, "TypeDefOrRef"),  # 9 InterfaceImpl
    ("MemberRefParent", "S", "B"),  # 10 MemberRef
    ("w2", "HasConstant", "B"),  # 11 Constant
    ("HasCustomAttribute", "CustomAttributeType", "B"),  # 12 CustomAttribute
    ("HasFieldMarshal", "B"),  # 13 FieldMarshal
    ("w2", "HasDeclSecurity", "B"),  # 14 DeclSecurity
    ("w2", "w4", 2),  # 15 ClassLayout
    ("w4", 4),  # 16 FieldLayout
    ("B",),  # 17 StandAloneSig
    (2, 20),  # 18 EventMap
    (20,),  # 19 EventPtr
    ("w2", "S", "TypeDefOrRef"),  # 20 Event
    (2, 23),  # 21 PropertyMap
    (23,),  # 22 PropertyPtr
    ("w2", "S", "B"),  # 23 Property
    ("w2", 6, "HasSemantics"),  # 24 MethodSemantics
    (2, "MethodDefOrRef", "MethodDefOrRef"),  # 25 MethodImpl
    ("S",),  # 26 ModuleRef
    ("B",),  # 27 TypeSpec
    ("w2", "MemberForwarded", "S", 26),  # 28 ImplMap
    ("w4", 4),  # 29 FieldRVA
    ("w4", "w4"),  # 30 ENCLog
    ("w4",),  # 31 ENCMap
    ("w4", "w2", "w2", "w2", "w2", "w4", "B", "S", "S"),  # 32 Assembly
    ("w4",),  # 33 AssemblyProcessor
    ("w4", "w4", "w4"),  # 34 AssemblyOS
    ("w2", "w2", "w2", "w2", "w4", "B", "S", "S", "B"),  # 35 AssemblyRef
    ("w4", 35),  # 36 AssemblyRefProcessor
    ("w4", "w4", "w4", 35),  # 37 AssemblyRefOS
    ("w4", "S", "B"),  # 38 File
    ("w4", "w4", "S", "S", "Implementation"),  # 39 ExportedType
    ("w4", "w4", "S", "Implementation"),  # 40 ManifestResource
    (2, 2),  # 41 NestedClass
    ("w2", "w2", "TypeOrMethodDef", "S"),  # 42 GenericParam
    ("MethodDefOrRef", "B"),  # 43 MethodSpec
    (42, "TypeDefOrRef"),  # 44 GenericParamConstraint
)


class Stream(NamedTuple):
    name: str
    offset: int  # in the file
    size: int


class Assembly(NamedTuple):
    name: bytes
    version: tuple[int, int, int, int]


class Pinvoke(NamedTuple):
    row: int
    offset: int  # of the ImplMap row in the file
    length: int
    flags: int
    module: (
        bytes | None
    )  # None: an empty name, as C++/CLI writes for native code of the file itself
    function: bytes | None  # None: an empty import name, the same C++/CLI form
    method: bytes | None  # the method that forwards to it, when ImplMap names a method


class Member(NamedTuple):
    row: int
    offset: int
    length: int
    parent: str  # the table MemberRef.Class points to
    assembly: bytes | None  # for a type of another assembly
    namespace: bytes | None
    type: bytes | None
    name: bytes
    member: str  # "field" or "method", by its signature


class Type(NamedTuple):
    row: int
    offset: int
    length: int
    flags: int
    namespace: bytes | None
    name: bytes
    methods: int


class UserString(NamedTuple):
    entry: int  # where its entry starts in #US
    offset: int  # of its first character in the file
    characters: int  # it has
    raw: bytes  # the UTF-16LE bytes published, up to the character limit


class Metadata(NamedTuple):
    offset: int  # of the metadata root in the file
    length: int  # of the root, up to the end of its stream headers
    version: str
    flags: int  # of the CLI header
    entry_point: int  # token or RVA, as the CLI header declares it
    streams: tuple[Stream, ...]
    rows: tuple[int, ...]  # of each of the 45 tables
    assembly: Assembly | None
    assembly_refs: tuple[Assembly, ...]
    assembly_refs_total: int
    pinvokes: tuple[Pinvoke, ...]
    members: tuple[Member, ...]
    types: tuple[Type, ...]
    unreadable: int  # rows left out because a name or an index could not be read
    user_strings: tuple[UserString, ...]
    user_entries: int  # entries of #US that are not empty, among those examined
    user_complete: bool  # whether #US was examined to its end


def _regions(data: bytes) -> tuple[int, int, tuple[tuple[int, int, int], ...]]:
    """The CLR directory (RVA, size) and the section regions of a PE file, or ValueError."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt + 24 + 2 > len(data) or data[nt : nt + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    count = struct.unpack_from("<H", data, nt + 6)[0]
    optional_size = struct.unpack_from("<H", data, nt + 20)[0]
    optional = nt + 24
    fixed = {267: 96, 523: 112}.get(struct.unpack_from("<H", data, optional)[0])
    if fixed is None or optional + optional_size > len(data) or optional_size < fixed:
        raise ValueError("not a PE file")
    directories = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    if directories <= CLR_DIRECTORY or fixed + 8 * directories > optional_size:
        raise ValueError("no CLR directory")
    rva, size = struct.unpack_from("<II", data, optional + fixed + 8 * CLR_DIRECTORY)
    table = optional + optional_size
    if not 1 <= count <= SECTIONS_MAX or table + 40 * count > len(data):
        raise ValueError("unreadable section table")
    regions = []
    for index in range(count):
        _, base, raw_size, raw_offset = struct.unpack_from("<IIII", data, table + 40 * index + 8)
        if raw_size and raw_offset + raw_size <= len(data):
            regions.append((base, raw_offset, raw_size))
    return rva, size, tuple(regions)


def _locate(regions: tuple[tuple[int, int, int], ...], rva: int, size: int) -> int:
    """The file offset of `size` bytes at `rva`, if exactly one section holds them."""
    found = [
        offset + rva - base
        for base, offset, length in regions
        if base <= rva and rva + size <= base + length
    ]
    if size < 1 or len(found) != 1:
        raise ValueError("an RVA of the metadata has no single place in the file")
    return found[0]


class _Heaps:
    def __init__(self, data: bytes, streams: dict[str, Stream]):
        self.data = data
        self.strings = streams.get("#Strings")
        self.blob = streams.get("#Blob")

    def name(self, index: int) -> bytes:
        """A name of #Strings: UTF-8 up to its NUL, not empty and not longer than NAME_MAX."""
        heap = self.strings
        if heap is None or not 0 < index < heap.size:
            raise ValueError("a name lies outside #Strings")
        start = heap.offset + index
        end = self.data.find(b"\0", start, min(heap.offset + heap.size, start + NAME_MAX + 1))
        if end <= start:
            raise ValueError("a name is empty, too long or not terminated")
        return self.data[start:end]

    def optional(self, index: int) -> bytes | None:
        return None if index == 0 else self.name(index)

    def blob_first(self, index: int) -> int:
        """The first byte of a blob (II.24.2.4), after its compressed length."""
        heap = self.blob
        if heap is None or not 0 < index < heap.size:
            raise ValueError("a blob lies outside #Blob")
        at = heap.offset + index
        first = self.data[at]
        skip = 1 if first & 0x80 == 0 else 2 if first & 0xC0 == 0x80 else 4
        if first & 0xE0 == 0xE0 or index + skip >= heap.size:
            raise ValueError("a blob has no valid length")
        length = (
            int.from_bytes(self.data[at : at + skip], "big") & (0x7F, 0x3FFF, 0x1FFFFFFF)[skip // 2]
        )
        if length < 1 or index + skip + length > heap.size:
            raise ValueError("a blob lies outside #Blob")
        return self.data[at + skip]


class _Tables:
    def __init__(self, data: bytes, stream: Stream):
        if stream.size < 24:
            raise ValueError("the #~ stream is shorter than its header")
        base = stream.offset
        heap_sizes = data[base + 6]
        if heap_sizes & ~0x07:
            raise ValueError("the #~ header declares data the standard does not define")
        valid = struct.unpack_from("<Q", data, base + 8)[0]
        if valid >> TABLES:
            raise ValueError("the #~ stream has tables beyond the standard's 45")
        present = [index for index in range(TABLES) if valid >> index & 1]
        if 24 + 4 * len(present) > stream.size:
            raise ValueError("the #~ stream is shorter than its row counts")
        rows = [0] * TABLES
        for position, index in enumerate(present):
            rows[index] = struct.unpack_from("<I", data, base + 24 + 4 * position)[0]
        if any(count > ROWS_MAX for count in rows):
            raise ValueError("a table has more rows than a token can address")
        if any(rows[index] for index in POINTER_TABLES):
            raise ValueError("pointer tables belong to the unoptimized layout")
        self.data = data
        self.rows = tuple(rows)
        heap = {"S": heap_sizes & 1, "G": heap_sizes & 2, "B": heap_sizes & 4}
        self.widths: list[tuple[int, ...]] = []
        for columns in SCHEMA:
            widths = []
            for column in columns:
                if isinstance(column, int):
                    widths.append(4 if rows[column] > 0xFFFF else 2)
                elif column in ("w2", "w4"):
                    widths.append(int(column[1]))
                elif column in heap:
                    widths.append(4 if heap[column] else 2)
                else:
                    targets = CODED[column]
                    bits = (len(targets) - 1).bit_length()
                    largest = max(rows[t] for t in targets if t is not None)
                    widths.append(4 if largest >= 1 << (16 - bits) else 2)
            self.widths.append(tuple(widths))
        self.sizes = tuple(sum(widths) for widths in self.widths)
        self.starts: list[int] = []
        at = base + 24 + 4 * len(present)
        for index in range(TABLES):
            self.starts.append(at)
            at += self.sizes[index] * rows[index]
        if at > base + stream.size:
            raise ValueError("the tables do not fit in the #~ stream")

    def row(self, table: int, number: int) -> tuple[int, tuple[int, ...]]:
        """The file offset and the columns of row `number` (from 1)."""
        if not 1 <= number <= self.rows[table]:
            raise ValueError("a row index lies outside its table")
        offset = self.starts[table] + (number - 1) * self.sizes[table]
        values, at = [], offset
        for width in self.widths[table]:
            values.append(int.from_bytes(self.data[at : at + width], "little"))
            at += width
        return offset, tuple(values)

    @staticmethod
    def coded(kind: str, value: int) -> tuple[int, int]:
        """(table, row) of a coded index; ValueError for an unused tag."""
        targets = CODED[kind]
        bits = (len(targets) - 1).bit_length()
        tag = value & ((1 << bits) - 1)
        table = targets[tag] if tag < len(targets) else None
        if table is None:
            raise ValueError("a coded index has a tag the standard leaves unused")
        return table, value >> bits


def _streams(data: bytes, root: int, size: int) -> tuple[str, int, tuple[Stream, ...]]:
    """The version, the length of the root and its streams (file offsets)."""
    if size < 20 or data[root : root + 4] != ROOT:
        raise ValueError("the metadata does not start with its signature")
    length = struct.unpack_from("<I", data, root + 12)[0]
    if not 1 <= length <= VERSION_MAX or length % 4 or 16 + length + 4 > size:
        raise ValueError("the metadata version has no valid length")
    raw = data[root + 16 : root + 16 + length].split(b"\0", 1)[0]
    if not raw or any(not 0x20 <= byte <= 0x7E for byte in raw):
        raise ValueError("the metadata version is not printable ASCII")
    at = root + 16 + length
    count = struct.unpack_from("<H", data, at + 2)[0]
    if not 1 <= count <= STREAMS_MAX:
        raise ValueError("the metadata declares no streams or too many")
    at += 4
    streams = []
    for _index in range(count):
        if at + 8 > root + size:
            raise ValueError("a stream header lies outside the metadata")
        offset, length = struct.unpack_from("<II", data, at)
        end = data.find(b"\0", at + 8, min(root + size, at + 8 + STREAM_NAME_MAX))
        if end < 0:
            raise ValueError("a stream name is not terminated")
        name = data[at + 8 : end]
        if not name or any(not 0x20 <= byte <= 0x7E for byte in name):
            raise ValueError("a stream name is not printable ASCII")
        if offset + length > size:
            raise ValueError("a stream lies outside the metadata")
        streams.append(Stream(name.decode("ascii"), root + offset, length))
        at = end + 1 + (-(end + 1 - (at + 8)) % 4)
    names = [stream.name for stream in streams]
    if len(names) != len(set(names)):
        raise ValueError("two streams share a name")
    if at > root + size:
        raise ValueError("the stream headers lie outside the metadata")
    return raw.decode("ascii"), at - root, tuple(streams)


def _type_ref(tables: _Tables, heaps: _Heaps, row: int) -> tuple[bytes | None, bytes | None, bytes]:
    """(assembly, namespace, name) of a TypeRef; the assembly of a nested type is the one
    its enclosing types reach within SCOPE_DEPTH steps."""
    _, (scope, name, namespace) = tables.row(TYPE_REF, row)
    found = (heaps.optional(namespace), heaps.name(name))
    for _step in range(SCOPE_DEPTH):
        table, target = _Tables.coded("ResolutionScope", scope)
        if table == ASSEMBLY_REF:
            reference = tables.row(ASSEMBLY_REF, target)[1]
            return (heaps.name(reference[6]), *found)
        if table != TYPE_REF:
            return (None, *found)  # a type of this module or of another module
        scope = tables.row(TYPE_REF, target)[1][0]
    raise ValueError("a nested type is deeper than the steps followed")


def _assembly(columns: tuple[int, ...], heaps: _Heaps, name: int) -> Assembly:
    major, minor, build, revision = columns[:4]
    return Assembly(heaps.name(columns[name]), (major, minor, build, revision))


def _user_strings(
    data: bytes, heap: Stream | None, characters: int
) -> tuple[tuple[UserString, ...], int, bool]:
    """The literals of #US (II.24.2.4) that are printable ASCII of at least
    USER_CHARACTERS characters, how many entries are not empty and whether the stream was
    examined to its end. An entry is its compressed length, UTF-16LE text and one final
    byte; one that does not fit in the stream ends the reading."""
    if heap is None:
        return (), 0, True
    found: list[UserString] = []
    entries, at = 0, 1
    for _step in range(USER_STEPS):
        if at >= heap.size:
            return tuple(found), entries, True
        if len(found) == USER_STRINGS:
            break
        first = data[heap.offset + at]
        skip = 1 if first & 0x80 == 0 else 2 if first & 0xC0 == 0x80 else 4
        if first & 0xE0 == 0xE0 or at + skip > heap.size:
            break
        prefix = data[heap.offset + at : heap.offset + at + skip]
        length = int.from_bytes(prefix, "big") & (0x7F, 0x3FFF, 0x1FFFFFFF)[skip // 2]
        entry, start = at, at + skip
        if start + length > heap.size:
            break
        at = start + length
        if length == 0:
            continue
        entries += 1
        text = data[heap.offset + start : heap.offset + start + length - 1]
        count = len(text) // 2
        if length % 2 == 0 or count < USER_CHARACTERS:
            continue
        if any(text[1::2]) or any(not 0x20 <= byte <= 0x7E for byte in text[::2]):
            continue
        found.append(UserString(entry, heap.offset + start, count, text[: 2 * characters]))
    return tuple(found), entries, False


def read(data: bytes, characters: int = 1024) -> Metadata | None:
    """The metadata of the assembly, None if the file has no CLR directory, ValueError if
    it has one that is not the layout this method reads. `characters` is how much of
    each literal of #US is kept."""
    try:
        rva, size, regions = _regions(data)
    except ValueError:
        return None
    if rva == 0:
        return None
    if size < CLI_SIZE:
        raise ValueError("the CLR directory is smaller than a CLI header")
    cli = _locate(regions, rva, CLI_SIZE)
    if struct.unpack_from("<I", data, cli)[0] != CLI_SIZE:
        raise ValueError("a CLI header declares its size, 72")
    meta_rva, meta_size, flags, entry_point = struct.unpack_from("<IIII", data, cli + 8)
    if meta_size < 20:
        raise ValueError("the CLI header declares no metadata")
    root = _locate(regions, meta_rva, meta_size)
    version, length, streams = _streams(data, root, meta_size)
    named = {stream.name: stream for stream in streams}
    if "#~" not in named or "#-" in named:
        raise ValueError("the metadata is not in the optimized layout")
    tables = _Tables(data, named["#~"])
    heaps = _Heaps(data, named)
    unreadable = 0

    assembly = None
    if tables.rows[ASSEMBLY]:
        try:
            assembly = _assembly(tables.row(ASSEMBLY, 1)[1][1:], heaps, 6)
        except ValueError:
            unreadable += 1
    references = []
    for number in range(1, min(tables.rows[ASSEMBLY_REF], ASSEMBLY_REFS) + 1):
        try:
            references.append(_assembly(tables.row(ASSEMBLY_REF, number)[1], heaps, 6))
        except ValueError:
            unreadable += 1

    pinvokes = []
    for number in range(1, min(tables.rows[IMPL_MAP], PINVOKES) + 1):
        try:
            offset, (mapping, forwarded, name, scope) = tables.row(IMPL_MAP, number)
            table, target = _Tables.coded("MemberForwarded", forwarded)
            method = None
            if table == METHOD_DEF:
                method = heaps.name(tables.row(METHOD_DEF, target)[1][3])
            pinvokes.append(
                Pinvoke(
                    number,
                    offset,
                    tables.sizes[IMPL_MAP],
                    mapping,
                    heaps.optional(tables.row(MODULE_REF, scope)[1][0]),
                    heaps.optional(name),
                    method,
                )
            )
        except ValueError:
            unreadable += 1

    members = []
    for number in range(1, min(tables.rows[MEMBER_REF], MEMBERS) + 1):
        try:
            offset, (parent, name, signature) = tables.row(MEMBER_REF, number)
            table, target = _Tables.coded("MemberRefParent", parent)
            origin: tuple[bytes | None, bytes | None, bytes | None] = (None, None, None)
            if table == TYPE_REF:
                origin = _type_ref(tables, heaps, target)
                kind = "type_ref"
            elif table == TYPE_DEF:
                own = tables.row(TYPE_DEF, target)[1]
                origin = (None, heaps.optional(own[2]), heaps.name(own[1]))
                kind = "type_def"
            elif table == MODULE_REF:
                origin = (None, None, heaps.name(tables.row(MODULE_REF, target)[1][0]))
                kind = "module_ref"
            elif table == METHOD_DEF:
                tables.row(METHOD_DEF, target)
                kind = "method_def"
            else:
                tables.row(TYPE_SPEC, target)
                kind = "type_spec"
            members.append(
                Member(
                    number,
                    offset,
                    tables.sizes[MEMBER_REF],
                    kind,
                    *origin,
                    heaps.name(name),
                    "field" if heaps.blob_first(signature) == 0x06 else "method",
                )
            )
        except ValueError:
            unreadable += 1

    types = []
    total = tables.rows[TYPE_DEF]
    for number in range(1, min(total, TYPES) + 1):
        try:
            offset, (type_flags, name, namespace, _extends, _fields, first) = tables.row(
                TYPE_DEF, number
            )
            last = (
                tables.row(TYPE_DEF, number + 1)[1][5]
                if number < total
                else tables.rows[METHOD_DEF] + 1
            )
            if not 1 <= first <= last <= tables.rows[METHOD_DEF] + 1:
                raise ValueError("a type's methods are not a run of the method table")
            types.append(
                Type(
                    number,
                    offset,
                    tables.sizes[TYPE_DEF],
                    type_flags,
                    heaps.optional(namespace),
                    heaps.name(name),
                    last - first,
                )
            )
        except ValueError:
            unreadable += 1

    return Metadata(
        root,
        length,
        version,
        flags,
        entry_point,
        streams,
        tables.rows,
        assembly,
        tuple(references),
        tables.rows[ASSEMBLY_REF],
        tuple(pinvokes),
        tuple(members),
        tuple(types),
        unreadable,
        *_user_strings(data, named.get("#US"), characters),
    )
