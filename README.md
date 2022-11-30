# cyber-etl
DSE 203 Project- Cybersecurity data merging from multiple sources to create and query a knowledge graph for insights.

## Files:
1. `parse_cve_json_data.py` - Script to convert NIST CVE JSON data into a format ready to import into Neo4j
2. `cve_node_data.feather` - Data for creating CVE nodes
3. `cve_references.feather` - Data for creating tag nodes and linking the tagged references to CVE nodes


## Loading data into neo4j:
Run the following in the neo4j database-

`	CALL apoc.periodic.iterate(
	"CALL apoc.load.json('file:///nvdcve-1.1-2022.json') YIELD value",
	"UNWIND value.CVE_Items AS data  \r\n"+
	"UNWIND data.cve.references.reference_data AS references \r\n"+
	"UNWIND data.publishedDate AS publishedDate \r\n"+
	"UNWIND data.cve.description.description_data AS description_data \r\n"+
	"UNWIND data.impact.baseMetricV3.exploitabilityScore AS exploitabilityScore \r\n"+
	"UNWIND data.impact.baseMetricV3.impactScore AS impactScore \r\n"+
	"UNWIND data.impact.baseMetricV3.cvssV3.baseScore AS baseScore \r\n"+
	"MERGE (cveItem:CVE {uid: apoc.create.uuid()}) \r\n"+
	"ON CREATE SET cveItem.cveid = data.cve.CVE_data_meta.ID, cveItem.publishedDate = publishedDate, cveItem.description = description_data.value, cveItem.exploitabilityScore = exploitabilityScore, cveItem.impactScore = impactScore, cveItem.baseScore = baseScore, cveItem.referenceURL = references.url, cveItem.referenceName = references.name, cveItem.referenceSource = references.refsource, cveItem.referenceTags = references.tags",
	 {batchSize:100, iterateList:true});`

This will create nodes with IDs, publishedDates, Descriptions, Scores, and References
