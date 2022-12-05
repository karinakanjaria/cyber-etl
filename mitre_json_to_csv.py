#!/usr/bin/python3
#
# FROM MITRE:
# https://raw.githubusercontent.com/sduff/mitre_attack_csv/main/mitre_attack_csv.py
#


# sourcery skip: avoid-builtin-shadow
import csv
import re

import requests

url = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
outfile = "data/enterprise-attack.csv"

print("Fetching latest enterprise-attack.json ...")
mitre_json_data = requests.get(url)
assert mitre_json_data.status_code == 200, "Failure fetching url"

print("Parsing file ...")
attack_json = mitre_json_data.json()
assert "spec_version" in attack_json, "Failure reading version info in JSON file"
assert "objects" in attack_json, "Failure reading objects in JSON file"
assert attack_json["spec_version"] == "2.0", "Unsupported STIX version"

all_objects = {}  # dict objects
for item in attack_json["objects"]:
    assert "type" in item, f"type information is missing in entry {item}"
    assert "id" in item, f"id field is missing in entry {item}"

    # skip revoked or deprecated items
    if ("revoked" in item and item["revoked"] is True) or (
        "x_mitre_deprecated" in item and item["x_mitre_deprecated"] is True
    ):
        continue

    _id = item["id"]
    item_type = item["type"]

    if item_type not in all_objects:
        all_objects[item_type] = {}
    all_objects[item_type][_id] = item

print("Generating list of tactics ...")

# Generate a list of tactics
tactics = {}
for item_type in all_objects["x-mitre-tactic"]:
    short_name = all_objects["x-mitre-tactic"][item_type]["x_mitre_shortname"]
    name = all_objects["x-mitre-tactic"][item_type]["name"]
    _id = all_objects["x-mitre-tactic"][item_type]["external_references"][0][
        "external_id"
    ]
    url = all_objects["x-mitre-tactic"][item_type]["external_references"][0]["url"]

    tactics[short_name] = name

# minature markdown


def minimd(s, fmt="text"):

    code = re.compile("<code>(?P<codeblock>.*?)</code>")

    bold = re.compile("\*\*(.*?)\*\*")
    link = re.compile("\[([^[]*?)\]\((.*?)\)")
    header = re.compile("(?:^|\n)#+([^\n]*)")

    if fmt == "html":
        s = code.sub(
            lambda x: f'<code>{x.group("codeblock").replace("<", "&lt;")}</code>', s
        )

        s = bold.sub(r"<b>\1</b>", s)
        s = link.sub(r'<a href="\2">\1</a>', s)
        s = header.sub(r"<b><u>\1</u></b><br/>", s)

        # rewrite links to mitre page to this one (mitre to internal link)
        mtil = re.compile('"https://attack.mitre.org/techniques/(?P<technique>.*?)"')
        s = mtil.sub(lambda x: f'"#{x.group("technique").replace("/", ".")}"', s)

        s = s.replace("\n", "<br/>")

    elif fmt == "text":
        # tidy headers
        s = header.sub(r"# \1 #\n", s)

        # neaten code
        s = code.sub(lambda x: f'`{x.group("codeblock")}`', s)

        # rewrite links to mitre page to plaintext
        mtil = re.compile(
            'https://attack.mitre.org/(techniques|tactics|software)/(?P<technique>[^\])"]+)'
        )
        s = mtil.sub(lambda x: f'{x.group("technique").replace("/", ".")}', s)

        # remove <br>
        s = s.replace("<br>", "\n")

    return s


print("Generating list of techniques ...")
# Generate a list of techniques
tech = {}
for tn in all_objects["attack-pattern"]:
    item_type = all_objects["attack-pattern"][tn]

    mitre_id = ""
    mitre_url = ""
    if "external_references" in item_type:
        for r in item_type["external_references"]:
            if "source_name" in r and r["source_name"] == "mitre-attack":
                mitre_id = r["external_id"]
                mitre_url = r["url"]
    assert mitre_id != "", f"Didn't find a mitre id for {item_type}"

    name = item_type["name"] if "name" in item_type else ""
    platforms = (
        item_type["x_mitre_platforms"] if "x_mitre_platforms" in item_type else []
    )
    kill_chain_phases = (
        item_type["kill_chain_phases"] if "kill_chain_phases" in item_type else []
    )
    kill_chain_phases = [
        tactics[x["phase_name"]]
        for x in kill_chain_phases
        if x["kill_chain_name"] == "mitre-attack"
    ]
    data_sources = (
        item_type["x_mitre_data_sources"] if "x_mitre_data_sources" in item_type else []
    )
    description = item_type["description"] if "description" in item_type else ""
    description = minimd(description)
    detection = (
        item_type["x_mitre_detection"] if "x_mitre_detection" in item_type else ""
    )
    detection = minimd(detection)

    tech[mitre_id] = (
        name,
        tn,
        mitre_url,
        platforms,
        kill_chain_phases,
        data_sources,
        detection,
        description,
    )

print("Generating CSV file ...")
with open(outfile, "w", newline="\n") as out:
    writer = csv.DictWriter(
        out,
        [
            "name",
            "id",
            "url",
            "platforms",
            "kill chain phases",
            "description",
            "data sources",
            "detection",
        ],
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()

    for tid in sorted(tech.keys()):
        item_type = tech[tid]

        name = item_type[0]
        tn = item_type[1]
        mitre_url = item_type[2]
        platforms = ", ".join(item_type[3])
        kill_chain_phases = ", ".join(item_type[4])
        data_sources = ", ".join(item_type[5])
        detection = item_type[6]
        description = item_type[7]

        writer.writerow(
            {
                "name": name,
                "id": tid,
                "url": mitre_url,
                "platforms": platforms,
                "kill chain phases": kill_chain_phases,
                "description": description,
                "data sources": data_sources,
                "detection": detection,
            }
        )
