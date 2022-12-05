import gzip
import json
from pathlib import Path

import jsonpath_ng as jq
import jsonpath_ng.ext as jqe
import pandas as pd
import requests

range_of_cve = "*"  # "0:10"  # 0: means from zero to the end
data_path = Path("./data")
cve_filename_stub = "nvdcve-1.1-"

# Get all the CVE JSON Data
years_to_grab = range(2002, 2023)
for year in years_to_grab:
    filename = f"{cve_filename_stub}{year}.json.gz"
    url = f"https://nvd.nist.gov/feeds/json/cve/1.1/{filename}"
    cve_file_path = data_path / filename
    if not cve_file_path.exists():
        nist_response = requests.get(url)
        if nist_response.status_code == 200:
            with open(cve_file_path, "wb") as cve_file:
                cve_file.write(nist_response.content)
                print(f"Downloaded {filename} successfully.", end="\r", flush=True)
        else:
            print(f"Unable to get the CVE data for {year}")
print("Download effort complete.")

# List of all the CVE JSON data we could download
json_file_paths = data_path.glob(f"{cve_filename_stub}*.json.gz")

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
cpe_path = jqe.parse(
    "configurations.nodes.[*].cpe_match[?(@.vulnerable==true)].cpe23Uri,versionEndIncluding"
)

cve_data_dict = {
    "cve_id": [],
    "score": [],
    "exploitability": [],
    "impact": [],
    "published": [],
    "refs": [],
    "description": [],
    "cpes": [],
}

for json_file_path in json_file_paths:
    if not json_file_path.exists():
        raise FileNotFoundError(
            f"Could not find the NIST CVE Data JSON file: {json_file_path}"
        )

    with gzip.open(json_file_path, "r") as jsonfile:
        json_data = json.loads(jsonfile.read())

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

            # CVSSv3 Scores
            cve_score = score_path.find(cve_item)
            cve_score = cve_score[0].value if cve_score else None
            cve_data_dict["score"].append(cve_score)

            cve_exploitability = exploitability_path.find(cve_item)
            cve_exploitability = (
                cve_exploitability[0].value if cve_exploitability else None
            )
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

            # CPE Data
            this_cve_cpes = [
                "_".join(this_one.value.split(":")[3:5])
                for this_one in cpe_path.find(cve_item)
            ]
            cpe_data = pd.DataFrame(
                pd.Series(this_cve_cpes, dtype="string")
                .rename("cpe")
                .reset_index()
                .drop_duplicates()
            )
            cpe_data["cve_id"] = cve_id
            cve_data_dict["cpes"].append(cpe_data)

cve_data = (
    pd.DataFrame(cve_data_dict).drop(["refs", "cpes"], axis=1).reset_index(drop=True)
)
cve_references = (
    pd.concat(cve_data_dict["refs"])
    .explode("tags")
    .reset_index(drop=True)
    .rename(columns={"tags": "tag"})
)
cve_cpes = (
    pd.concat(cve_data_dict["cpes"])
    .explode("cpe")
    .reset_index(drop=True)
    .drop(columns="index")
    .drop_duplicates()
    .reset_index(drop=True)
)

cve_references.to_csv(data_path / "cve_references.csv", index=False)
cve_cpes.to_csv(data_path / "cpe_node_data.csv", index=False)
cve_data.to_csv(data_path / "cve_node_data.csv", index=False)

cve_references.to_feather(data_path / "cve_references.feather")
cve_cpes.to_feather(data_path / "cpe_node_data.feather")
cve_data.to_feather(data_path / "cve_node_data.feather")
