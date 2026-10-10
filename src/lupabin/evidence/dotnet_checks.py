"""The .NET metadata facts of a sample, derived the same way by the worker (which
publishes them) and by the host (which accepts a report only if it derives them again
from the sample's bytes)."""

from collections.abc import Sequence

from lupabin.evidence import dotnet
from lupabin.evidence.facts import (
    DotnetAssembly,
    DotnetMemberData,
    DotnetMetadataData,
    DotnetPinvokeData,
    DotnetStream,
    DotnetStringData,
    DotnetTypeData,
    Evidence,
)
from lupabin.evidence.primitives import Location, Name

Payload = (
    DotnetMetadataData | DotnetPinvokeData | DotnetStringData | DotnetMemberData | DotnetTypeData
)
ROOT_KEY = "pe:dotnet"
KINDS = ("dotnet_metadata", "dotnet_pinvoke", "dotnet_string", "dotnet_member", "dotnet_type")


def _name(raw: bytes | None) -> Name | None:
    return None if raw is None else Name.from_bytes(raw)


def _required(raw: bytes) -> Name:
    return Name.from_bytes(raw)


def _assembly(found: dotnet.Assembly) -> DotnetAssembly:
    return DotnetAssembly(name=_required(found.name), version=found.version)


def truncated(metadata: dotnet.Metadata) -> bool:
    """Whether the assembly has more rows than the ones this method publishes."""
    return (
        metadata.assembly_refs_total > dotnet.ASSEMBLY_REFS
        or metadata.rows[dotnet.IMPL_MAP] > dotnet.PINVOKES
        or metadata.rows[dotnet.MEMBER_REF] > dotnet.MEMBERS
        or metadata.rows[dotnet.TYPE_DEF] > dotnet.TYPES
        or not metadata.user_complete
    )


def derive(
    data: bytes, characters: int
) -> tuple[dotnet.Metadata, list[tuple[str, Payload, Location]]] | None:
    """(metadata, [(key, payload, location)]) in the order they are published: the
    metadata first, then what it declares. None if the file is not an assembly;
    ValueError if its metadata is not in the layout the method reads. `characters` is
    the report's limit for a string."""
    metadata = dotnet.read(data, characters)
    if metadata is None:
        return None
    rows = metadata.rows
    facts: list[tuple[str, Payload, Location]] = [
        (
            ROOT_KEY,
            DotnetMetadataData(
                version=metadata.version,
                flags=metadata.flags,
                entry_point=metadata.entry_point,
                streams=tuple(
                    DotnetStream(name=stream.name, offset=stream.offset, size=stream.size)
                    for stream in metadata.streams
                ),
                type_refs=rows[dotnet.TYPE_REF],
                type_defs=rows[dotnet.TYPE_DEF],
                methods=rows[dotnet.METHOD_DEF],
                member_refs=rows[dotnet.MEMBER_REF],
                module_refs=rows[dotnet.MODULE_REF],
                pinvokes=rows[dotnet.IMPL_MAP],
                assembly_refs=metadata.assembly_refs_total,
                assembly=None if metadata.assembly is None else _assembly(metadata.assembly),
                references=tuple(_assembly(item) for item in metadata.assembly_refs),
                unreadable=metadata.unreadable,
                user_strings=metadata.user_entries,
            ),
            Location(offset=metadata.offset, length=metadata.length),
        )
    ]
    for call in metadata.pinvokes:
        facts.append(
            (
                f"pe:dotnet:pinvoke:{call.row}",
                DotnetPinvokeData(
                    row=call.row,
                    flags=call.flags,
                    module=_name(call.module),
                    function=_name(call.function),
                    method=_name(call.method),
                ),
                Location(offset=call.offset, length=call.length),
            )
        )
    for literal in metadata.user_strings:
        kept = len(literal.raw) // 2
        facts.append(
            (
                f"pe:dotnet:string:{literal.entry}",
                DotnetStringData(
                    index=literal.entry,
                    encoding="utf-16-le",
                    text=literal.raw.decode("utf-16-le"),
                    raw_hex=literal.raw.hex(),
                    characters=kept,
                    complete=kept == literal.characters,
                    total_characters=literal.characters,
                ),
                Location(offset=literal.offset, length=len(literal.raw)),
            )
        )
    for member in metadata.members:
        facts.append(
            (
                f"pe:dotnet:member:{member.row}",
                DotnetMemberData(
                    row=member.row,
                    parent=member.parent,  # type: ignore[arg-type]
                    assembly=_name(member.assembly),
                    namespace=_name(member.namespace),
                    type=_name(member.type),
                    name=_required(member.name),
                    member=member.member,  # type: ignore[arg-type]
                ),
                Location(offset=member.offset, length=member.length),
            )
        )
    for found in metadata.types:
        facts.append(
            (
                f"pe:dotnet:type:{found.row}",
                DotnetTypeData(
                    row=found.row,
                    flags=found.flags,
                    namespace=_name(found.namespace),
                    name=_required(found.name),
                    methods=found.methods,
                ),
                Location(offset=found.offset, length=found.length),
            )
        )
    return metadata, facts


def verify_dotnet(evidence: Sequence[Evidence], data: bytes, characters: int) -> None:
    """Raise unless every .NET fact is one the sample's bytes give again, at the same
    place, in the same order and with nothing in between left out."""
    published = [fact for fact in evidence if fact.kind in KINDS]
    if not published:
        return
    derived = derive(data, characters)
    if derived is None:
        raise ValueError("the sample has no .NET metadata")
    expected = derived[1]
    if len(published) > len(expected):
        raise ValueError("more .NET facts than the sample's metadata gives")
    for fact, (_, payload, location) in zip(published, expected, strict=False):
        if fact.data != payload or fact.location != location:
            raise ValueError(".NET fact differs from the sample's metadata")
