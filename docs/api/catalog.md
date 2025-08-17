# Catalog API Endpoints

The catalog endpoints manage ATT&CK releases and provide access to tactics and other framework components.

## GET /catalog/attack/releases

List available ATT&CK releases from the official MITRE repository.

### Request

```http
GET /v1/catalog/attack/releases
```

### Response

```json
{
  "releases": [
    {
      "collection": "enterprise-attack",
      "version": "15.1",
      "release_date": "2024-04-23",
      "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json",
      "attack_spec_version": "2.1.0",
      "stix_version": "2.1"
    },
    {
      "collection": "enterprise-attack",
      "version": "15.0",
      "release_date": "2024-03-05",
      "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.0.json",
      "attack_spec_version": "2.1.0",
      "stix_version": "2.1"
    }
  ]
}
```

### Fields

- **collection**: The ATT&CK collection name (e.g., "enterprise-attack", "mobile-attack", "ics-attack")
- **version**: The ATT&CK version number
- **release_date**: ISO date when this version was released
- **url**: Direct URL to download the STIX bundle
- **attack_spec_version**: ATT&CK specification version
- **stix_version**: STIX specification version

### Example

```bash
curl -X GET http://localhost:8000/v1/catalog/attack/releases
```

### Notes

- Fetches from the official ATT&CK index at GitHub
- Results are cached for performance
- Use version "latest" to get the most recent release

---

## GET /catalog/tactics

Get all ATT&CK tactics with their STIX IDs and shortnames.

### Request

```http
GET /v1/catalog/tactics
```

### Response

```json
{
  "tactics": [
    {
      "stix_id": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
      "shortname": "reconnaissance",
      "name": "Reconnaissance",
      "description": "The adversary is trying to gather information they can use to plan future operations.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0043",
          "url": "https://attack.mitre.org/tactics/TA0043"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
      "shortname": "resource-development",
      "name": "Resource Development",
      "description": "The adversary is trying to establish resources they can use to support operations.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0042",
          "url": "https://attack.mitre.org/tactics/TA0042"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--daa4cbb1-b4f4-4723-a824-7f1efd6e0592",
      "shortname": "initial-access",
      "name": "Initial Access",
      "description": "The adversary is trying to get into your network.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0001",
          "url": "https://attack.mitre.org/tactics/TA0001"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
      "shortname": "execution",
      "name": "Execution",
      "description": "The adversary is trying to run malicious code.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0002",
          "url": "https://attack.mitre.org/tactics/TA0002"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936582c8",
      "shortname": "persistence",
      "name": "Persistence",
      "description": "The adversary is trying to maintain their foothold.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0003",
          "url": "https://attack.mitre.org/tactics/TA0003"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
      "shortname": "privilege-escalation",
      "name": "Privilege Escalation",
      "description": "The adversary is trying to gain higher-level permissions.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0004",
          "url": "https://attack.mitre.org/tactics/TA0004"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--78b23412-0651-46d7-9f01-17026f595dd9",
      "shortname": "defense-evasion",
      "name": "Defense Evasion",
      "description": "The adversary is trying to avoid being detected.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0005",
          "url": "https://attack.mitre.org/tactics/TA0005"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--8c0eb900-2290-464e-84e9-aa29033b83e5",
      "shortname": "credential-access",
      "name": "Credential Access",
      "description": "The adversary is trying to steal account names and passwords.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0006",
          "url": "https://attack.mitre.org/tactics/TA0006"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--3f0ca812-2e3e-4c91-992d-87d5ec67f1fa",
      "shortname": "discovery",
      "name": "Discovery",
      "description": "The adversary is trying to figure out your environment.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0007",
          "url": "https://attack.mitre.org/tactics/TA0007"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
      "shortname": "lateral-movement",
      "name": "Lateral Movement",
      "description": "The adversary is trying to move through your environment.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0008",
          "url": "https://attack.mitre.org/tactics/TA0008"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--2e34237a-ddcb-4e39-9df8-0508117f3579",
      "shortname": "collection",
      "name": "Collection",
      "description": "The adversary is trying to gather data of interest to their goal.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0009",
          "url": "https://attack.mitre.org/tactics/TA0009"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813",
      "shortname": "command-and-control",
      "name": "Command and Control",
      "description": "The adversary is trying to communicate with compromised systems to control them.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0011",
          "url": "https://attack.mitre.org/tactics/TA0011"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462",
      "shortname": "exfiltration",
      "name": "Exfiltration",
      "description": "The adversary is trying to steal data.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0010",
          "url": "https://attack.mitre.org/tactics/TA0010"
        }
      ]
    },
    {
      "stix_id": "x-mitre-tactic--5569339b-94c2-49ee-afb3-12f0f1b0e622",
      "shortname": "impact",
      "name": "Impact",
      "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "TA0040",
          "url": "https://attack.mitre.org/tactics/TA0040"
        }
      ]
    }
  ]
}
```

### Fields

- **stix_id**: STIX 2.1 identifier for the tactic
- **shortname**: Short name used in kill chain phases (e.g., "initial-access")
- **name**: Human-readable tactic name (e.g., "Initial Access")
- **description**: Brief description of adversary goals for this tactic
- **external_references**: ATT&CK website references with TA codes

### Example

```bash
curl -X GET http://localhost:8000/v1/catalog/tactics
```

### Usage Notes

- This endpoint is used by the LLM tool-calling system to ground tactic references
- Results are cached after first call for performance
- Tactics are returned in kill chain order
- Use the shortname for matching against kill_chain_phases in techniques

### Error Responses

- **500 Internal Server Error**: Database connection failed or tactics not loaded

```json
{
  "detail": "No tactics found. Ensure ATT&CK data is loaded."
}
```