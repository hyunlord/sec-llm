"""Static per-source metadata: identity, endpoints, and license findings.

Every license value here was read from the source's own documentation on
2026-09-18 and the governing sentence is quoted in `license_evidence`. Nothing
is inferred from a similar project. Where a question is not answered by the
source's own documents, the value is "unknown" and the evidence field says what
was checked -- see in particular `weights_release`, which none of the four
sources address.
"""

from __future__ import annotations

LICENSE_CHECK_DATE = "2026-09-18"

# Shared across all four: these are vulnerability catalogues, not people
# datasets, but every one of them has free-text fields (descriptions, credits,
# references) that can carry a researcher's name. That is a P2 scanning
# obligation, not an absence of risk.
PII_POLICY_COMMON = (
    "no_intentional_pii; free-text description/credit/reference fields may carry "
    "researcher or reporter names -- P2 secret/PII scanning is required"
)

SOURCES = {
    "cve_list": {
        "source_id": "cve_list",
        "source_name": "CVE List V5 (CVEProject/cvelistV5)",
        "source_url": "https://github.com/CVEProject/cvelistV5",
        "content_type": "cve_record_v5_json",
        "entity_id_field": "cveMetadata.cveId",
        "license": {
            "source_license": "CVE Program Terms of Use (The MITRE Corporation)",
            "source_license_url": "https://www.cve.org/Legal/TermsOfUse",
            "upstream_license": (
                "CNA submissions under the CVE Program Terms of Use submitter grant "
                "(submitters grant MITRE and all CNAs a perpetual, royalty-free, "
                "irrevocable copyright license)"
            ),
            "redistribution_status": "permitted_with_attribution",
            # not_addressed, not permitted_with_attribution. The evidence quoted
            # below says in as many words that "commercial" does not appear in
            # the CVE Terms of Use. A machine-readable field that asserts more
            # than the prose beside it is the defect, whichever one is wrong.
            "commercial_status": "not_addressed",
            "contains_third_party_content": True,
            "pii_policy": PII_POLICY_COMMON,
            "license_evidence": (
                "CVE Usage: \"MITRE hereby grants you a perpetual, worldwide, "
                "non-exclusive, no-charge, royalty-free, irrevocable copyright license "
                "to reproduce, prepare derivative works of, publicly display, publicly "
                "perform, sublicense, and distribute Common Vulnerabilities and "
                "Exposures (CVE). Any copy you make for such purposes is authorized "
                "provided that you reproduce MITRE's copyright designation and this "
                "license in any such copy.\" The grant carries no field-of-use "
                "restriction, but note that -- unlike CWE and ATT&CK -- the word "
                "\"commercial\" does not appear in the CVE Terms of Use."
            ),
            "weights_release": "not_addressed",
            "weights_release_evidence": (
                "The Terms of Use grant the right to prepare derivative works and to "
                "distribute them, and impose an attribution condition. They do not "
                "mention machine learning, training, or model weights in any form. "
                "Whether a trained weight is a derivative work of the training corpus "
                "is not settled by this document. Legal review required."
            ),
            "model_publication_status": "not_addressed",
            "checked_on": LICENSE_CHECK_DATE,
        },
        "repo": "CVEProject/cvelistV5",
        "records_glob": "cves/**/CVE-*.json",
    },
    "nvd": {
        "source_id": "nvd",
        "source_name": "NVD CVE API 2.0 (NIST National Vulnerability Database)",
        "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "content_type": "nvd_cve_api_2_0_json",
        "entity_id_field": "cve.id",
        "license": {
            "source_license": (
                "US Government work, public domain under 17 U.S.C. (NIST publication); "
                "NVD requests a source-attribution notice"
            ),
            "source_license_url": "https://nvd.nist.gov/developers/start-here",
            "upstream_license": (
                "CVE Program Terms of Use (The MITRE Corporation) -- the CVE records "
                "embedded in every NVD response originate from the CVE Program and are "
                "NOT a US Government work; only NVD's own analysis (CVSS scoring, CPE "
                "applicability, CWE mapping) is public domain"
            ),
            "redistribution_status": "permitted_with_attribution",
            "commercial_status": "permitted_with_attribution",
            "contains_third_party_content": True,
            "pii_policy": PII_POLICY_COMMON,
            "license_evidence": (
                "\"All NIST publications are available in the public domain according to "
                "Title 17 of the United States Code, however services which utilize or "
                "access the NVD are asked to display the following notice prominently "
                "within the application: 'This product uses data from the NVD API but is "
                "not endorsed or certified by the NVD.' You may use the NVD name to "
                "identify the source of the data. You may not use the NVD name, to imply "
                "endorsement of any product, service, or entity, not-for-profit, "
                "commercial or otherwise.\" Commercial use is therefore contemplated; only "
                "use of the NVD *name* to imply endorsement is restricted."
            ),
            "weights_release": "not_addressed",
            "weights_release_evidence": (
                "NVD's own analysis being public domain places no restriction on weight "
                "release. The embedded CVE content is a different matter and inherits the "
                "CVE Terms of Use, which do not address model weights. This is precisely "
                "why source_license and upstream_license are separate fields."
            ),
            "attribution_notice_required": (
                "This product uses data from the NVD API but is not endorsed or certified "
                "by the NVD."
            ),
            "model_publication_status": "not_addressed",
            "checked_on": LICENSE_CHECK_DATE,
        },
        # Documented at https://nvd.nist.gov/developers/start-here, read 2026-09-18:
        #   public (no key): 5 requests in a rolling 30 second window
        #   with API key:   50 requests in a rolling 30 second window
        #   recommended:    sleep 6 seconds between requests
        "rate_limit": {
            "public_requests_per_window": 5,
            "api_key_requests_per_window": 50,
            "window_seconds": 30,
            "recommended_sleep_seconds": 6,
            "api_key_required": False,
            "api_key_env_var": "NVD_API_KEY",
            "documentation_url": "https://nvd.nist.gov/developers/start-here",
            "documentation_read_on": LICENSE_CHECK_DATE,
        },
        "results_per_page": 2000,
    },
    "cwe": {
        "source_id": "cwe",
        "source_name": "CWE (Common Weakness Enumeration) versioned XML catalog",
        "source_url": "https://cwe.mitre.org/data/downloads.html",
        "content_type": "cwe_catalog_xml",
        "entity_id_field": "Weakness/@ID -> CWE-<id>",
        "license": {
            "source_license": "CWE Terms of Use (The MITRE Corporation)",
            "source_license_url": "https://cwe.mitre.org/about/termsofuse.html",
            "upstream_license": (
                "Community contributions under the CWE Terms of Use contributor grant "
                "(contributors grant all users a perpetual, worldwide, non-exclusive, "
                "no-charge, royalty-free, irrevocable license)"
            ),
            "redistribution_status": "permitted_with_attribution",
            "commercial_status": "permitted_with_attribution",
            "contains_third_party_content": True,
            "pii_policy": PII_POLICY_COMMON,
            "license_evidence": (
                "\"CWE is free to use by any organization or individual for any research, "
                "development, and/or commercial purposes, per these CWE Terms of Use. "
                "Accordingly, The MITRE Corporation hereby grants you a non-exclusive, "
                "royalty-free license to use CWE for research, development, and commercial "
                "purposes. Any copy you make for such purposes is authorized on the "
                "condition that you reproduce MITRE's copyright designation and this "
                "license in any such copy.\""
            ),
            "weights_release": "not_addressed",
            "weights_release_evidence": (
                "Commercial use is granted explicitly, but the Terms of Use do not mention "
                "training or model weights. The contributor grant does include the right to "
                "\"prepare derivative works\". Legal review required."
            ),
            "model_publication_status": "not_addressed",
            "checked_on": LICENSE_CHECK_DATE,
        },
        "version_probe_url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "versioned_url_template": "https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip",
    },
    "attack": {
        "source_id": "attack",
        "source_name": "MITRE ATT&CK STIX 2.1 bundles (mitre-attack/attack-stix-data)",
        "source_url": "https://github.com/mitre-attack/attack-stix-data",
        "content_type": "stix_2_1_bundle_json",
        "entity_id_field": "external_references[source_name=mitre-attack].external_id",
        "license": {
            "source_license": "MITRE ATT&CK License (LICENSE.txt in attack-stix-data)",
            "source_license_url": "https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt",
            "upstream_license": (
                "Same MITRE ATT&CK License; individual STIX objects carry "
                "external_references to third-party vendor threat reports, which are "
                "cited but not redistributed"
            ),
            "redistribution_status": "permitted_with_attribution",
            "commercial_status": "permitted_with_attribution",
            "contains_third_party_content": True,
            "pii_policy": PII_POLICY_COMMON,
            "license_evidence": (
                "\"The MITRE Corporation (MITRE) hereby grants you a non-exclusive, "
                "royalty-free license to use ATT&CK for research, development, and "
                "commercial purposes. Any copy you make for such purposes is authorized "
                "provided that you reproduce MITRE's copyright designation and this "
                "license in any such copy.\" Required designation: \"(c) 2026 The MITRE "
                "Corporation. This work is reproduced and distributed with the permission "
                "of The MITRE Corporation.\""
            ),
            "weights_release": "not_addressed",
            "weights_release_evidence": (
                "Commercial use is granted explicitly. The license is silent on machine "
                "learning, training corpora, and model weights. Legal review required."
            ),
            "model_publication_status": "not_addressed",
            "checked_on": LICENSE_CHECK_DATE,
        },
        "repo": "mitre-attack/attack-stix-data",
        "domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
    },
}

# Replay set for P3. Not ingested by ingest/run.py (no MODULES entry); consumed
# by datasets/replay.py. Listed here so the license matrix and the claim audit
# hold it to the same evidence standard as the four security sources.
SOURCES["replay_oasst2"] = {
    "source_id": "replay_oasst2",
    "source_name": "OpenAssistant/oasst2 (general-instruction replay set)",
    "source_url": "https://huggingface.co/datasets/OpenAssistant/oasst2",
    "content_type": "instruction_response_pair",
    "entity_id_field": "message_id",
    "phase": "P3",
    "license": {
        "source_license": "Apache License 2.0 (declared in the dataset card: `license: apache-2.0`)",
        "source_license_url": "https://huggingface.co/datasets/OpenAssistant/oasst2/blob/main/README.md",
        "upstream_license": (
            "Human volunteer contributions to the Open Assistant project, released by the "
            "project under the same Apache-2.0 declaration; model-generated messages "
            "(`synthetic: true`, with the generating model named) exist in the raw data "
            "and are EXCLUDED from the replay set so no third model's terms apply"
        ),
        "redistribution_status": "permitted_with_attribution",
        "commercial_status": "not_addressed",
        "contains_third_party_content": True,
        "pii_policy": (
            "crowd-written conversations may contain names, emails and personal details; "
            "the P2 secret/PII scan is applied to every selected pair and counts are reported"
        ),
        "license_evidence": (
            "Dataset card frontmatter, read 2026-09-19 at commit 179dd21f: "
            "`license: apache-2.0`. The repository ships NO separate LICENSE file; the "
            "declaration is the card's SPDX field. Apache License 2.0 section 2 grants "
            "\"a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable "
            "copyright license to reproduce, prepare Derivative Works of, publicly display, "
            "publicly perform, sublicense, and distribute the Work and such Derivative Works "
            "in Source or Object form\"; section 4 conditions redistribution on retaining "
            "attribution and NOTICE. The word \"commercial\" does not appear in the Apache "
            "License 2.0 text; the grant carries no field-of-use restriction. Held to the "
            "same standard as cve_list, that is not_addressed rather than permitted."
        ),
        "weights_release": "not_addressed",
        "weights_release_evidence": (
            "Apache-2.0 grants the right to prepare and distribute Derivative Works broadly, "
            "but does not mention machine learning, training, or model weights. Whether a "
            "trained weight is a Derivative Work of the training corpus is not settled by the "
            "license text. Same open question as the four security sources; legal review "
            "required."
        ),
        "model_publication_status": "not_addressed",
        "checked_on": "2026-09-19",
        "candidates_rejected": {
            "databricks/databricks-dolly-15k": "cc-by-sa-3.0 -- ShareAlike imposes a copyleft condition on derivatives; mixed obligations",
            "HuggingFaceH4/no_robots": "cc-by-nc-4.0 -- NonCommercial",
            "allenai/tulu-3-sft-mixture": "odc-by, but a MIXTURE of sources with differing underlying licenses; unclear/mixed",
            "GAIR/lima": "license 'other' (CC-BY-NC-SA on inspection); NonCommercial + ShareAlike",
            "nvidia/HelpSteer2": "cc-by-4.0 -- acceptable license, NOT rejected on license; not chosen because responses are model-generated, which brings a generating model's terms into scope. Recorded as the fallback.",
        },
    },
}

SOURCE_ORDER = ["cve_list", "nvd", "cwe", "attack"]          # ingested by ingest/run.py
DOC_ORDER = SOURCE_ORDER + ["replay_oasst2"]                  # appears in the license matrix


def license_block(source_id: str) -> dict:
    """The subset of license metadata that goes into every record's lineage."""
    lic = SOURCES[source_id]["license"]
    return {
        "source_license": lic["source_license"],
        "upstream_license": lic["upstream_license"],
        "redistribution_status": lic["redistribution_status"],
        "commercial_status": lic["commercial_status"],
        "model_publication_status": lic["model_publication_status"],
        "contains_third_party_content": lic["contains_third_party_content"],
        "pii_policy": lic["pii_policy"],
    }
