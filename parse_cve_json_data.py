import gzip
import json
from pathlib import Path

import jsonpath_ng as jq
import numpy as np
import pandas as pd
from dateutil import parser

# JSONPATH!
range_of_cve = "0:"
json_file_path = Path("nvdcve-1.1-2022.json.gz")
if not json_file_path.exists():
    raise FileNotFoundError("Could not find the NIST CVE Data JSON file.")

with gzip.open(json_file_path, "r") as jsonfile:
    json_data = json.loads(jsonfile.read())

# JSON Path Queries
path_cve_items = jq.parse(f"$.CVE_Items.[{range_of_cve}]")
cve_path = jq.parse("cve")
id_path = jq.parse("CVE_data_meta.ID")
publish_path = jq.parse("publishedDate")
metric_path = jq.parse("impact.baseMetricV3")
exploitability_path = jq.parse("impact.baseMetricV3.exploitabilityScore")
impact_path = jq.parse("impact.baseMetricV3.impactScore")
score_path = jq.parse("impact.baseMetricV3.cvssV3.baseScore")
ref_path = jq.parse("references.reference_data.[*]")
desc_path = jq.parse("description.description_data.[*].value")

cve_data_dict = {
    "cve_id": [],
    "score": [],
    "exploitability": [],
    "impact": [],
    "published": [],
    "refs": [],
    "description": [],
}

cve_items = path_cve_items.find(json_data)
for cve_item in cve_items:
    for item in cve_path.find(cve_item):
        # Get the ID
        cve_id = id_path.find(item)[0].value
        cve_data_dict["cve_id"].append(cve_id)

        # Get the References
        cve_refs = [ref.value for ref in ref_path.find(item)]
        for ref in cve_refs:
            ref["cve_id"] = cve_id
        cve_data_dict["refs"].append(pd.DataFrame(cve_refs))

        cve_score = score_path.find(cve_item)
        cve_score = cve_score[0].value if cve_score else None
        cve_data_dict["score"].append(cve_score)

        cve_exploitability = exploitability_path.find(cve_item)
        cve_exploitability = cve_exploitability[0].value if cve_exploitability else None
        cve_data_dict["exploitability"].append(cve_exploitability)

        cve_impact = impact_path.find(cve_item)
        cve_impact = cve_impact[0].value if cve_impact else None
        cve_data_dict["impact"].append(cve_impact)

        cve_date = publish_path.find(cve_item)[0].value
        cve_data_dict["published"].append(cve_date)

        # Get the Description
        cve_desc = [desc.value for desc in desc_path.find(item)]
        description = " -|- ".join(cve_desc)
        cve_data_dict["description"].append(description)
cve_data = pd.DataFrame(cve_data_dict).drop(["refs"], axis=1).reset_index(drop=True)
cve_references = (
    pd.concat(cve_data_dict["refs"])
    .explode("tags")
    .reset_index(drop=True)
    .rename(columns={"tags": "tag"})
)

cve_references.to_csv("cve_references.csv", index=False)
cve_data.to_csv("cve_node_data.csv", index=False)
cve_references.to_feather("cve_references.feather")
cve_data.to_feather("cve_node_data.feather")
