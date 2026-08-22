"""Phase 8 — rendering. No module here talks to the network or a model."""


# Who argued, who attacked, who read the refutation. Kept here rather than in
# one renderer: the JSON report carried it and the Markdown and HTML ones did
# not, so two of the four ways of reading an audit hid the panel's entire
# point. A shared reader is what stops that happening a second time.
JUDGEMENT_KEYS = (
    ("moteur", "argumenté par"),
    ("contradicteur", "attaqué par"),
    ("second contradicteur", "puis par"),
    ("relecture", "réfutation relue par"),
    ("phase", "phase"),
)


def judgement(finding) -> list[tuple[str, str]]:
    """The stages this finding went through, in order, as (label, value)."""
    provenance = finding.provenance or {}
    return [
        (label, str(provenance[key]))
        for key, label in JUDGEMENT_KEYS
        if provenance.get(key)
    ]
