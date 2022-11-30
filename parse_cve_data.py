import json
from pathlib import Path

import jsonpath_ng as jq
import numpy as np
import pandas as pd
from dateutil import parser

# JSONPATH!
range_of_cve = "1:3"
path_cve_items = jq.parse(f"$.CVE_Items.[{range_of_cve}]")  # .cve.CVE_data_meta.ID")
path_cve_ids = jq.parse(f"$.CVE_Items.[{range_of_cve}].cve.CVE_data_meta.ID")
path_cve_references = jq.parse(
    f"$.CVE_Items.[{range_of_cve}].cve.references.reference_data"
)
with open("/home/chris/Downloads/nvdcve-1.1-2022.json", "r") as jsonfile:
    json_data = json.loads(jsonfile.read())

cve_items = path_cve_items.find(json_data)
cve_path = jq.parse("cve")
id_path = jq.parse("CVE_data_meta.ID")
score_path = jq.parse("impact.baseMetricV3.cvssV3.baseScore")
publish_path = jq.parse("publishedDate")
ref_path = jq.parse("references.reference_data.[*]")
desc_path = jq.parse("description.description_data.[*].value")

cve_data_dict = {
    "cve_id": [],
    "score": [],
    "published": [],
    "refs": [],
    "description": [],
}
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

        cve_score = score_path.find(cve_item)[0].value
        cve_data_dict["score"].append(cve_score)

        cve_date = publish_path.find(cve_item)[0].value
        cve_data_dict["published"].append(cve_date)

        # Get the Description
        cve_desc = [desc.value for desc in desc_path.find(item)]
        description = " -|- ".join(cve_desc)
        cve_data_dict["description"].append(description)
cve_data = pd.DataFrame(cve_data_dict)
cve_references = pd.concat(cve_data["refs"].to_list())
breakpoint()
print(cve_references)
print(cve_data)