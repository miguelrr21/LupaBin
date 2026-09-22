from collections.abc import Sequence

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import DecodedStringEvidence, Evidence, StringEvidence
from dissect.evidence.primitives import Source, Transform
from dissect.extractors import decode_strings, decode_xor
from dissect.extractors.base import Extraction

# The longest crib must fit in a decoded run; smaller character budgets block XOR
# instead of publishing runs longer than the report's own string limit.
_MIN_XOR_CHARS = 64


class DecodeExtractor:
    source: Source = "decode"
    version = "dissect-decode-v1"

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction:
        self._strings(collector, progress)
        self._xor(data, collector, progress)
        return Extraction("unknown", progress)

    def _strings(self, collector: Collector, progress: Progress) -> None:
        keys = {public: key for key, public in collector.ids.items()}
        sources = [fact for fact in collector.facts if isinstance(fact, StringEvidence)]
        progress.examined["decode_strings"] = len(sources)
        published = 0
        for fact in sources:
            for name, decoded in decode_strings.decodings(fact):
                if published >= collector.limits.decode.strings:
                    progress.issue("decode_strings", "decode_strings_limit", limit=True)
                    return
                if not collector.add(
                    f"decode:{name}:{fact.id}",
                    progress,
                    "decode_strings",
                    decode_strings.decoded_data(decoded),
                    fact.location,
                    refs=(keys[fact.id],),
                    extra={"transform": Transform(name=name)},
                ):
                    return  # the collector recorded why
                published += 1
        progress.complete("decode_strings")

    def _xor(self, data: bytes, collector: Collector, progress: Progress) -> None:
        limits = collector.limits
        if limits.string_characters < _MIN_XOR_CHARS:
            progress.issue("decode_xor", "decoded_length_limit", limit=True, blocked=True)
            return
        result = decode_xor.scan(
            data,
            max_hits=limits.decode.xor,
            max_examined=limits.decode.xor_examined,
            max_chars=limits.string_characters,
        )
        progress.examined["decode_xor"] = result.examined
        if result.examined_limit:
            progress.issue("decode_xor", "decode_xor_examined_limit", limit=True)
        if result.hit_limit:
            progress.issue("decode_xor", "decode_xor_limit", limit=True)
        for hit in result.hits:
            built = decode_xor.parts(hit)
            if not collector.add(
                f"decode:xor:{hit.start}:{hit.end}:{hit.encoding}:{hit.key.hex()}",
                progress,
                "decode_xor",
                built.data,
                built.location,
                extra={"transform": built.transform, "anchor": built.anchor},
            ):
                return
            if not hit.complete:
                progress.issue("decode_xor", "decoded_length_limit", limit=True)
        progress.complete("decode_xor")


def verify_decodings(evidence: Sequence[Evidence], data: bytes) -> None:
    """Re-derive every published decoding from the original bytes; raise if one differs."""
    facts = {fact.id: fact for fact in evidence}
    for fact in evidence:
        if not isinstance(fact, DecodedStringEvidence):
            continue
        if fact.transform.name == "xor-repeating-v1":
            decode_xor.verify(fact, data)
            continue
        cited = facts.get(fact.provenance.evidence_ids[0])
        if not isinstance(cited, StringEvidence):
            raise ValueError("a Base64/hex decoding must cite a string")
        decode_strings.verify(fact, cited, data)
