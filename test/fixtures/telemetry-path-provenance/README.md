# telemetry-path-provenance

Vulnerable: a resolver accepts bare relative local paths; outbound analytics calls a classifier which rejects only absolute/dot-prefixed paths and accepts two-segment catalog-shaped strings. Input team/private-tool leaks its components. Cite resolver, classifier and sink.
Clean: resolver returns a tagged Local reference and telemetry emits only local; verified public catalog references can retain IDs. A classifier used only in local debugging is outside this concern. A slash alone proves nothing.

These are review-policy calibration cases, not a measured model-recall claim.
