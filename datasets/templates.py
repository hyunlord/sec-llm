"""Fixed instruction templates. Three per task, chosen by a stable hash of the
example id. No language model writes any instruction or target -- that would
introduce an unpinned dependency and variation nobody can measure.
"""

from __future__ import annotations

from datasets.common import stable_int

TEMPLATES = {
    "cve_to_cwe": [
        "Classify the following vulnerability description into its CWE. Respond with JSON of the form "
        "{{\"cwe_id\": \"CWE-NNN\"}} and nothing else.\n\nDescription:\n{input}",
        "Read this CVE description and identify the single most appropriate CWE identifier. "
        "Output only JSON: {{\"cwe_id\": \"...\"}}.\n\n{input}",
        "Vulnerability description:\n{input}\n\nWhat is the CWE ID for this weakness? Answer as JSON "
        "{{\"cwe_id\": \"...\"}}.",
    ],
    "cvss_vector": [
        "Score the following vulnerability using CVSS v3.1 base metrics. Return a JSON object with the keys "
        "attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, "
        "integrityImpact, availabilityImpact, baseScore, vectorString.\n\nDescription:\n{input}",
        "From this CVE description, derive the CVSS v3.1 base vector and score. Respond only with JSON "
        "containing the eight base metrics, baseScore and vectorString.\n\n{input}",
        "Vulnerability:\n{input}\n\nProvide the CVSS 3.1 base metrics as JSON (attackVector, attackComplexity, "
        "privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, "
        "baseScore, vectorString).",
    ],
    "attack_technique": [
        "Identify the MITRE ATT&CK technique described below. Respond with JSON of the form "
        "{{\"technique_id\": \"T1234\"}} or {{\"technique_id\": \"T1234.001\"}} for a sub-technique.\n\n{input}",
        "Which ATT&CK technique ID does this description correspond to? Output only JSON: "
        "{{\"technique_id\": \"...\"}}.\n\nDescription:\n{input}",
        "Technique description:\n{input}\n\nGive the MITRE ATT&CK identifier as JSON {{\"technique_id\": \"...\"}}.",
    ],
    "structured_extract": [
        "Extract the affected vendor, product, affected versions, and stated impact from this vulnerability "
        "description. Return JSON with keys vendor, product, versions (array of strings), impact "
        "(string or null).\n\nDescription:\n{input}",
        "From the CVE text below, produce a JSON object {{\"vendor\": ..., \"product\": ..., \"versions\": [...], "
        "\"impact\": ...}}. Use null for impact if none is stated.\n\n{input}",
        "Vulnerability description:\n{input}\n\nStructure it as JSON: vendor, product, versions (list), "
        "impact (or null).",
    ],
}


def pick(task: str, example_id: str) -> tuple[int, str]:
    tpl = TEMPLATES[task]
    i = stable_int("tpl:" + example_id, len(tpl))
    return i, tpl[i]


def render(task: str, example_id: str, input_text: str) -> tuple[int, str]:
    i, t = pick(task, example_id)
    return i, t.format(input=input_text)
