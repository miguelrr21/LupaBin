from dissect.evidence.facts import AnomalyEvidence, Evidence


def validate_anomaly(fact: AnomalyEvidence, facts: dict[str, Evidence]) -> None:
    refs = [facts[ref] for ref in fact.provenance.evidence_ids]
    sections = [ref.data for ref in refs if ref.kind == "section"]
    headers = [ref.data for ref in refs if ref.kind == "pe_header"]
    if tuple(section.index for section in sections) != fact.data.section_indices:
        raise ValueError("anomaly indices disagree with referenced sections")
    code = fact.data.code
    valid = False
    if code == "section_raw_out_of_bounds" and len(sections) == 1 and not headers:
        valid = sections[0].raw_status == "out_of_bounds"
    elif code == "entry_point_outside_image" and len(headers) == 1 and not sections:
        valid = (
            bool(headers[0].entry_point_rva)
            and headers[0].entry_point_rva >= headers[0].size_of_image
        )
    elif code == "section_exceeds_image" and len(sections) == len(headers) == 1:
        section = sections[0]
        valid = section.rva + max(section.raw_size, section.virtual_size) > headers[0].size_of_image
    elif (
        code in ("section_raw_overlap", "section_virtual_overlap")
        and len(sections) == 2
        and not headers
    ):
        left, right = sections
        if code == "section_raw_overlap":
            start_a, size_a, start_b, size_b = (
                left.raw_offset,
                left.raw_size,
                right.raw_offset,
                right.raw_size,
            )
        else:
            start_a, size_a = left.rva, max(left.virtual_size, left.raw_size)
            start_b, size_b = right.rva, max(right.virtual_size, right.raw_size)
        valid = (
            size_a > 0
            and size_b > 0
            and max(start_a, start_b) < min(start_a + size_a, start_b + size_b)
        )
    if not valid:
        raise ValueError("anomaly is not supported by its referenced fields")
