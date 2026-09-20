"""P7 publication artifacts: the six documents and the SPDX SBOM.

Everything under this package is a generator. No number in a published
document is typed here; each one is read from a manifest or a run output at
build time and is registered with the path it came from, so that
`python -m docs.trace_check --assert-all` can re-resolve it independently.
"""
