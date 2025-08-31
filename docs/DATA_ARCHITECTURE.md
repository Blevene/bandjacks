# Bandjacks Data Architecture

## Table of Contents
1. [Overview](#overview)
2. [Data Storage Strategy](#data-storage-strategy)
3. [Neo4j Graph Database](#neo4j-graph-database)
4. [OpenSearch Document Store](#opensearch-document-store)
5. [Data Flow Patterns](#data-flow-patterns)
6. [STIX 2.1 Compliance](#stix-21-compliance)
7. [Schema Management](#schema-management)
8. [Data Quality & Validation](#data-quality--validation)
9. [Backup & Recovery](#backup--recovery)
10. [Performance Optimization](#performance-optimization)

## Overview

The Bandjacks data architecture implements a **hybrid storage strategy** combining graph and document databases to optimize different data access patterns. The design prioritizes **STIX 2.1 compliance**, **MITRE ATT&CK integration**, and **evidence-based provenance tracking**.

### **Core Design Principles**
- **Standards Compliance**: Full STIX 2.1 and ATT&CK Data Model (ADM) compliance
- **Evidence Provenance**: Every data point linked to source evidence
- **Immutable Audit Trail**: Complete history of data transformations
- **Performance Optimization**: Query patterns drive storage decisions
- **Scalability**: Horizontal scaling for growing threat intelligence

### **Storage Systems Overview**
| System | Primary Use Case | Data Types | Query Patterns |
|--------|------------------|------------|----------------|
| **Neo4j** | Relationship traversal, STIX objects | Entities, relationships, attack flows | Graph traversal, pattern matching |
| **OpenSearch** | Vector search, document storage | Embeddings, reports, search indices | Vector similarity, full-text search |
| **File System** | Temporary processing | PDF uploads, cache files | Sequential read/write |

## Data Storage Strategy

### **Polyglot Persistence Architecture**

```
┌─────────────────────────────────────────────────────────────────┐
│                         Data Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │     Neo4j        │  │    OpenSearch    │  │   File System    ││
│  │   Port 7687      │  │   Port 9200      │  │   Temporary      ││
│  │                  │  │                  │  │                  ││
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ ┌──────────────┐ ││
│  │ │ STIX Objects │ │  │ │ Vector Index │ │  │ │ PDF Storage  │ ││
│  │ │ Relationships│ │  │ │ Report Store │ │  │ │ Upload Buffer│ ││
│  │ │ Attack Flows │ │  │ │ Embeddings   │ │  │ │ Cache Files  │ ││
│  │ │ Provenance   │ │  │ │ Search Index │ │  │ └──────────────┘ ││
│  │ └──────────────┘ │  │ └──────────────┘ │  │                  ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
┌─────────────────────────────────────────────────────────────────┐
│                    Data Access Layer                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │   Graph Store    │  │  Document Store  │  │    File Store    ││
│  │                  │  │                  │  │                  ││
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ ┌──────────────┐ ││
│  │ │STIX Mapper   │ │  │ │Report Store  │ │  │ │Upload Handler│ ││
│  │ │Flow Builder  │ │  │ │Vector Search │ │  │ │PDF Extractor │ ││
│  │ │Query Builder │ │  │ │Index Manager │ │  │ │Cache Manager │ ││
│  │ └──────────────┘ │  │ └──────────────┘ │  │ └──────────────┘ ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### **Data Distribution Strategy**

#### **Neo4j (Primary for Structured Intelligence)**
- **STIX 2.1 Objects**: Complete threat intelligence objects
- **Relationships**: Entity connections and attack flows
- **Provenance**: Source tracking and audit trails
- **Attack Patterns**: MITRE ATT&CK technique library

#### **OpenSearch (Primary for Search & Analytics)**
- **Vector Embeddings**: Semantic similarity search
- **Report Documents**: Full-text searchable report content
- **Processing Jobs**: Async job status and results
- **Search Indices**: Optimized query performance

#### **File System (Temporary Processing)**
- **PDF Uploads**: Incoming document storage
- **Processing Cache**: Intermediate extraction results
- **Static Assets**: Configuration and template files

## Neo4j Graph Database

### **Node Labels & Properties**

#### **Core STIX Objects**
```cypher
// Attack Pattern (MITRE ATT&CK Techniques)
(:AttackPattern {
    stix_id: "attack-pattern--uuid",
    name: "Spearphishing Attachment",
    external_id: "T1566.001", 
    description: "Adversaries may...",
    x_mitre_is_subtechnique: true,
    kill_chain_phases: ["initial-access"],
    created: datetime("2019-04-15T00:00:00Z"),
    modified: datetime("2024-08-15T00:00:00Z"),
    source: {
        collection: "enterprise-attack",
        version: "15.1",
        modified: "2024-08-15",
        url: "https://github.com/mitre-attack/...",
        adm_spec: "3.3.0",
        adm_sha: "abc123..."
    }
})

// Intrusion Set (Threat Actors)
(:IntrusionSet {
    stix_id: "intrusion-set--uuid",
    name: "APT29",
    description: "APT29 is threat group...",
    aliases: ["Cozy Bear", "The Dukes"],
    first_seen: datetime("2008-01-01T00:00:00Z"),
    resource_level: "government",
    x_bj_confidence: 95.0,
    x_bj_verified: true,
    created: datetime("2024-08-31T10:00:00Z")
})

// Malware
(:Software {
    stix_id: "malware--uuid",
    name: "SUNBURST",
    description: "SUNBURST is a backdoor...",
    is_malware: true,
    capabilities: ["backdoor", "trojan"],
    implementation_languages: ["C#", ".NET"],
    x_bj_confidence: 90.0
})

// Campaign
(:Campaign {
    stix_id: "campaign--uuid", 
    name: "SolarWinds Supply Chain",
    description: "Campaign targeting...",
    first_seen: datetime("2019-09-01T00:00:00Z"),
    last_seen: datetime("2020-12-31T00:00:00Z"),
    objective: "Intelligence collection"
})
```

#### **Operational Objects**
```cypher
// Report (Source Documents)
(:Report {
    stix_id: "report--uuid",
    name: "APT29 Analysis Report",
    description: "Analysis of APT29 campaign...",
    published: datetime("2024-08-31T00:00:00Z"),
    report_types: ["threat-report"],
    x_bj_extraction_status: "reviewed",
    x_bj_technique_count: 15,
    x_bj_confidence_avg: 87.5
})

// Attack Episode (Operational Sequences) 
(:AttackEpisode {
    episode_id: "episode--uuid",
    name: "APT29 Initial Access Sequence",
    description: "Email-based initial access...",
    source_ref: "report--uuid",
    action_count: 8,
    flow_type: "sequential",
    confidence: 85.0,
    created: datetime("2024-08-31T10:00:00Z")
})

// Attack Action (Individual Steps)
(:AttackAction {
    action_id: "action--uuid",
    name: "Spearphishing Email",
    description: "Send malicious attachment...",
    technique_ref: "attack-pattern--uuid",
    order: 1,
    confidence: 92.0,
    evidence: ["Email logs show targeted messages..."]
})
```

### **Relationship Types**

#### **STIX Relationships**
```cypher
// Standard STIX relationships
(IntrusionSet)-[:USES]->(AttackPattern)
(IntrusionSet)-[:USES]->(Software) 
(Software)-[:USES]->(AttackPattern)
(Campaign)-[:ATTRIBUTED_TO]->(IntrusionSet)
(AttackPattern)-[:MITIGATED_BY]->(CourseOfAction)

// ATT&CK specific relationships
(AttackPattern)-[:HAS_TACTIC]->(Tactic)
(AttackPattern)-[:SUBTECHNIQUE_OF]->(AttackPattern)
(AttackPattern)-[:DETECTED_BY]->(DataComponent)
```

#### **Operational Relationships**
```cypher
// Attack flow relationships
(AttackEpisode)-[:CONTAINS]->(AttackAction)
(AttackAction)-[:NEXT {probability: 0.85, rationale: "..."}]->(AttackAction)

// Provenance relationships  
(Report)-[:EXTRACTED]->(AttackPattern)
(Report)-[:CONTAINS]->(IntrusionSet)
(AttackAction)-[:DERIVED_FROM {line_refs: [45, 46]}]->(Report)

// Review relationships
(User)-[:REVIEWED {decision: "approved", timestamp: datetime()}]->(AttackPattern)
```

### **Schema Constraints & Indexes**

```cypher
// Unique constraints
CREATE CONSTRAINT stix_id_unique FOR (n:AttackPattern) REQUIRE n.stix_id IS UNIQUE;
CREATE CONSTRAINT external_id_unique FOR (n:AttackPattern) REQUIRE n.external_id IS UNIQUE;
CREATE CONSTRAINT episode_id_unique FOR (n:AttackEpisode) REQUIRE n.episode_id IS UNIQUE;

// Property indexes
CREATE INDEX attack_pattern_name FOR (n:AttackPattern) ON (n.name);
CREATE INDEX attack_pattern_tactic FOR (n:AttackPattern) ON (n.kill_chain_phases);
CREATE INDEX intrusion_set_name FOR (n:IntrusionSet) ON (n.name);
CREATE INDEX report_published FOR (n:Report) ON (n.published);

// Composite indexes for common queries
CREATE INDEX episode_source_confidence FOR (n:AttackEpisode) ON (n.source_ref, n.confidence);
CREATE INDEX action_technique_order FOR (n:AttackAction) ON (n.technique_ref, n.order);
```

### **Query Patterns**

#### **Technique Search & Traversal**
```cypher
// Find all techniques used by a threat actor
MATCH (is:IntrusionSet {name: "APT29"})-[:USES]->(ap:AttackPattern)
RETURN ap.external_id, ap.name, ap.kill_chain_phases
ORDER BY ap.external_id;

// Find attack flows containing specific technique
MATCH (ap:AttackPattern {external_id: "T1566.001"})<-[:TECHNIQUE_REF]-(aa:AttackAction)
MATCH (ae:AttackEpisode)-[:CONTAINS]->(aa)
MATCH (ae)<-[:EXTRACTED]-(r:Report)
RETURN ae.episode_id, r.name, aa.confidence
ORDER BY aa.confidence DESC;
```

#### **Attack Flow Analysis**
```cypher
// Get complete attack sequence with probabilities
MATCH (ae:AttackEpisode {episode_id: $episode_id})-[:CONTAINS]->(start:AttackAction)
WHERE NOT EXISTS((start)<-[:NEXT]-(:AttackAction))
MATCH path = (start)-[:NEXT*]->(end:AttackAction)
WHERE NOT EXISTS((end)-[:NEXT]->(:AttackAction))
RETURN [node in nodes(path) | {
    action_id: node.action_id,
    name: node.name,
    technique_ref: node.technique_ref,
    order: node.order
}] as sequence,
[rel in relationships(path) | rel.probability] as probabilities;
```

#### **Provenance Tracking**
```cypher
// Trace technique extraction back to source
MATCH (ap:AttackPattern {external_id: $technique_id})
MATCH (ap)<-[ext:EXTRACTED]-(r:Report)
OPTIONAL MATCH (aa:AttackAction {technique_ref: ap.stix_id})
OPTIONAL MATCH (aa)-[der:DERIVED_FROM]->(r)
RETURN ap.name as technique,
       r.name as source_report,
       ext.confidence as extraction_confidence,
       der.line_refs as evidence_lines,
       ext.reviewed_by as reviewer,
       ext.reviewed_at as review_date;
```

## OpenSearch Document Store

### **Index Strategy**

#### **Attack Nodes Index (`bandjacks_attack_nodes-v1`)**
```json
{
  "mappings": {
    "properties": {
      "stix_id": { "type": "keyword" },
      "external_id": { "type": "keyword" },
      "name": { "type": "text", "analyzer": "english" },
      "description": { "type": "text", "analyzer": "english" },
      "kill_chain_phases": { "type": "keyword" },
      "embedding": { 
        "type": "dense_vector", 
        "dims": 768,
        "index": true,
        "similarity": "cosine"
      },
      "created": { "type": "date" },
      "modified": { "type": "date" },
      "source": {
        "properties": {
          "collection": { "type": "keyword" },
          "version": { "type": "keyword" },
          "modified": { "type": "date" }
        }
      }
    }
  },
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 1,
    "index": {
      "knn": true,
      "knn.space_type": "cosinesimil"
    }
  }
}
```

#### **Reports Index (`bandjacks_reports`)**
```json
{
  "mappings": {
    "properties": {
      "report_id": { "type": "keyword" },
      "name": { "type": "text", "analyzer": "english" },
      "content": { "type": "text", "analyzer": "english" },
      "status": { "type": "keyword" },
      "created": { "type": "date" },
      "modified": { "type": "date" },
      "extraction": {
        "properties": {
          "techniques_count": { "type": "integer" },
          "claims_count": { "type": "integer" },
          "confidence_avg": { "type": "float" },
          "entities": {
            "properties": {
              "malware": { "type": "nested" },
              "threat_actors": { "type": "nested" },
              "campaigns": { "type": "nested" },
              "tools": { "type": "nested" }
            }
          },
          "claims": { 
            "type": "nested",
            "properties": {
              "external_id": { "type": "keyword" },
              "name": { "type": "text" },
              "quotes": { "type": "text" },
              "line_refs": { "type": "integer" },
              "confidence": { "type": "float" },
              "review_status": { "type": "keyword" }
            }
          },
          "flow": {
            "properties": {
              "flow_type": { "type": "keyword" },
              "confidence": { "type": "float" },
              "steps": { 
                "type": "nested",
                "properties": {
                  "technique_id": { "type": "keyword" },
                  "name": { "type": "text" },
                  "order": { "type": "integer" },
                  "confidence": { "type": "float" }
                }
              }
            }
          }
        }
      },
      "unified_review": {
        "properties": {
          "reviewer_id": { "type": "keyword" },
          "reviewed_at": { "type": "date" },
          "global_notes": { "type": "text" },
          "statistics": {
            "properties": {
              "total_reviewed": { "type": "integer" },
              "approved": { "type": "integer" },
              "rejected": { "type": "integer" },
              "edited": { "type": "integer" }
            }
          },
          "decisions": { 
            "type": "nested",
            "properties": {
              "item_id": { "type": "keyword" },
              "action": { "type": "keyword" },
              "timestamp": { "type": "date" },
              "notes": { "type": "text" }
            }
          }
        }
      }
    }
  }
}
```

#### **Attack Flows Index (`bandjacks_flows`)**
```json
{
  "mappings": {
    "properties": {
      "episode_id": { "type": "keyword" },
      "name": { "type": "text", "analyzer": "english" },
      "source_ref": { "type": "keyword" },
      "flow_type": { "type": "keyword" },
      "confidence": { "type": "float" },
      "action_count": { "type": "integer" },
      "techniques": { "type": "keyword" },
      "tactics": { "type": "keyword" },
      "embedding": { 
        "type": "dense_vector", 
        "dims": 768,
        "index": true,
        "similarity": "cosine"
      },
      "created": { "type": "date" },
      "actions": {
        "type": "nested",
        "properties": {
          "action_id": { "type": "keyword" },
          "technique_ref": { "type": "keyword" },
          "name": { "type": "text" },
          "order": { "type": "integer" },
          "confidence": { "type": "float" }
        }
      },
      "edges": {
        "type": "nested", 
        "properties": {
          "from": { "type": "keyword" },
          "to": { "type": "keyword" },
          "probability": { "type": "float" },
          "rationale": { "type": "text" }
        }
      }
    }
  }
}
```

### **Search Patterns**

#### **Vector Similarity Search**
```json
{
  "knn": {
    "embedding": {
      "vector": [0.1, 0.2, ...],
      "k": 10
    }
  },
  "_source": ["name", "description", "external_id", "kill_chain_phases"],
  "min_score": 0.7
}
```

#### **Hybrid Search (Vector + Text)**
```json
{
  "query": {
    "bool": {
      "should": [
        {
          "knn": {
            "embedding": {
              "vector": [0.1, 0.2, ...],
              "k": 10,
              "boost": 2.0
            }
          }
        },
        {
          "multi_match": {
            "query": "spearphishing email attachment",
            "fields": ["name^3", "description"],
            "type": "best_fields",
            "boost": 1.0
          }
        }
      ],
      "filter": [
        { "terms": { "kill_chain_phases": ["initial-access"] } }
      ]
    }
  }
}
```

#### **Aggregation Queries**
```json
{
  "query": { "match_all": {} },
  "aggs": {
    "techniques_by_tactic": {
      "terms": { 
        "field": "kill_chain_phases",
        "size": 20
      },
      "aggs": {
        "avg_confidence": {
          "avg": { "field": "extraction.confidence_avg" }
        }
      }
    },
    "reports_by_status": {
      "terms": { "field": "status" }
    },
    "extraction_timeline": {
      "date_histogram": {
        "field": "created",
        "calendar_interval": "week"
      }
    }
  }
}
```

## Data Flow Patterns

### **Ingestion Flow**

```
PDF Upload → Text Extraction → Chunking → LLM Processing → STIX Generation → Graph Storage
     ↓              ↓              ↓            ↓              ↓              ↓
File System → OpenSearch → Processing → OpenSearch → Neo4j → OpenSearch
(temp)         (reports)     (cache)     (embeddings)  (graph)   (indexed)
```

#### **Detailed Data Transformation**

1. **Document Processing**
   ```python
   # PDF → Text
   text = extract_text_from_pdf(pdf_file)
   chunks = create_chunks(text, chunk_size=3000)
   
   # Store in reports index
   report_doc = {
       "report_id": report_id,
       "content": text,
       "status": "processing",
       "created": datetime.utcnow()
   }
   opensearch.index("bandjacks_reports", report_doc)
   ```

2. **LLM Extraction**
   ```python
   # Extract techniques from chunks
   extraction_result = llm_pipeline.extract(chunks)
   
   # Update report with extraction data
   opensearch.update("bandjacks_reports", report_id, {
       "doc": {
           "extraction": extraction_result.dict(),
           "status": "extracted"
       }
   })
   ```

3. **Graph Population**
   ```python
   # Create STIX objects in Neo4j
   for technique in extraction_result.claims:
       stix_object = create_attack_pattern(technique)
       neo4j_session.run("""
           MERGE (ap:AttackPattern {stix_id: $stix_id})
           SET ap += $properties
           """, stix_id=stix_object.id, properties=stix_object.dict())
       
       # Create extraction relationship
       neo4j_session.run("""
           MATCH (r:Report {stix_id: $report_id})
           MATCH (ap:AttackPattern {stix_id: $technique_id}) 
           MERGE (r)-[:EXTRACTED {
               confidence: $confidence,
               line_refs: $line_refs,
               evidence: $evidence
           }]->(ap)
           """, 
           report_id=report_id,
           technique_id=stix_object.id,
           confidence=technique.confidence,
           line_refs=technique.line_refs,
           evidence=technique.quotes
       )
   ```

### **Review Flow**

```
Report → Review Interface → Decisions → Validation → Atomic Update → Graph Update
   ↓          ↓               ↓           ↓              ↓              ↓
OpenSearch → Frontend → Local State → Backend → OpenSearch → Neo4j
(report)    (UI)      (decisions)   (API)     (reviewed)    (approved)
```

#### **Review Data Processing**

1. **Decision Collection**
   ```typescript
   const decisions: UnifiedReviewDecision[] = [
       {
           item_id: "entity-malware-0",
           action: "approve",
           timestamp: "2024-08-31T10:00:00Z"
       },
       {
           item_id: "technique-5",
           action: "edit",
           edited_value: { name: "Corrected Technique Name" },
           confidence_adjustment: 85,
           notes: "Fixed technique identification",
           timestamp: "2024-08-31T10:01:00Z"
       }
   ]
   ```

2. **Atomic Update Processing**
   ```python
   # Update report with review decisions
   update_doc = {
       "doc": {
           "unified_review": {
               "reviewer_id": submission.reviewer_id,
               "reviewed_at": submission.review_timestamp,
               "decisions": [d.dict() for d in submission.decisions],
               "statistics": calculate_statistics(submission.decisions)
           },
           "status": "reviewed"
       }
   }
   
   # Apply changes to extraction data
   for decision in submission.decisions:
       if decision.action == "approve":
           # Create/update graph nodes
           create_approved_entity(decision, neo4j_session)
       elif decision.action == "reject":
           # Mark as rejected but preserve in report
           update_extraction_status(decision, "rejected")
   ```

### **Search Flow**

```
User Query → Embedding → Vector Search → Results Ranking → Response
     ↓           ↓            ↓               ↓             ↓
  Frontend → LLM Service → OpenSearch → Post-processing → Frontend
   (UI)     (embedding)    (KNN)         (relevance)      (display)
```

## STIX 2.1 Compliance

### **STIX Domain Objects**

The system maintains full STIX 2.1 compliance with proper object structure:

```python
# Attack Pattern (MITRE ATT&CK Technique)
attack_pattern = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--{uuid}",
    "created": "2024-08-31T10:00:00.000Z",
    "modified": "2024-08-31T10:00:00.000Z",
    "name": "Spearphishing Attachment",
    "description": "Adversaries may send...",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mitre-attack",
            "phase_name": "initial-access"
        }
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1566.001",
            "url": "https://attack.mitre.org/techniques/T1566/001"
        }
    ],
    "x_mitre_is_subtechnique": True,
    "x_mitre_platforms": ["Linux", "macOS", "Windows"],
    "x_mitre_data_sources": ["Email Gateway", "File"]
}

# Intrusion Set (Threat Actor)
intrusion_set = {
    "type": "intrusion-set", 
    "spec_version": "2.1",
    "id": "intrusion-set--{uuid}",
    "created": "2024-08-31T10:00:00.000Z",
    "modified": "2024-08-31T10:00:00.000Z",
    "name": "APT29",
    "description": "APT29 is a threat group...",
    "aliases": ["Cozy Bear", "The Dukes"],
    "first_seen": "2008-01-01T00:00:00.000Z",
    "resource_level": "government",
    "goals": ["Intelligence Collection"],
    "sophistication": "expert"
}

# Relationship (Entity using Technique)
relationship = {
    "type": "relationship",
    "spec_version": "2.1", 
    "id": "relationship--{uuid}",
    "created": "2024-08-31T10:00:00.000Z",
    "modified": "2024-08-31T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "intrusion-set--{uuid}",
    "target_ref": "attack-pattern--{uuid}",
    "x_bj_confidence": 90.0,
    "x_bj_evidence": ["Report describes APT29 using..."],
    "x_bj_source_report": "report--{uuid}"
}
```

### **STIX Bundle Generation**

```python
def generate_stix_bundle(report_data: dict) -> dict:
    """Generate STIX 2.1 compliant bundle from report data."""
    
    objects = []
    
    # Create report object
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": report_data["name"],
        "published": datetime.utcnow().isoformat() + "Z",
        "report_types": ["threat-report"],
        "object_refs": []
    }
    
    # Add entities as STIX objects
    for entity_type, entities in report_data.get("entities", {}).items():
        for entity in entities:
            if entity.get("review_status") == "approved":
                stix_obj = create_stix_entity(entity, entity_type)
                objects.append(stix_obj)
                report_obj["object_refs"].append(stix_obj["id"])
    
    # Add techniques as attack patterns
    for claim in report_data.get("claims", []):
        if claim.get("review_status") == "approved":
            attack_pattern = create_stix_attack_pattern(claim)
            objects.append(attack_pattern)
            report_obj["object_refs"].append(attack_pattern["id"])
    
    objects.append(report_obj)
    
    return {
        "type": "bundle",
        "spec_version": "2.1", 
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects
    }
```

### **ADM Validation**

```python
def validate_adm_compliance(stix_bundle: dict) -> dict:
    """Validate STIX bundle against ATT&CK Data Model."""
    
    validation_results = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    for obj in stix_bundle.get("objects", []):
        # Validate required properties
        if obj["type"] == "attack-pattern":
            if not obj.get("external_references"):
                validation_results["errors"].append(
                    f"Attack pattern {obj['id']} missing external_references"
                )
            
            # Check for valid technique ID
            ext_refs = obj.get("external_references", [])
            mitre_refs = [ref for ref in ext_refs if ref.get("source_name") == "mitre-attack"]
            if not mitre_refs:
                validation_results["errors"].append(
                    f"Attack pattern {obj['id']} missing MITRE external reference"
                )
        
        # Validate custom extensions
        for key, value in obj.items():
            if key.startswith("x_mitre_") and obj["type"] != "attack-pattern":
                validation_results["warnings"].append(
                    f"Object {obj['id']} has MITRE extension on non-attack-pattern"
                )
    
    validation_results["valid"] = len(validation_results["errors"]) == 0
    return validation_results
```

## Schema Management

### **Database Migrations**

#### **Neo4j Schema Evolution**
```cypher
// V1.0 - Initial schema
CREATE CONSTRAINT stix_id_unique FOR (n) REQUIRE n.stix_id IS UNIQUE;

// V1.1 - Add provenance tracking
CREATE (:Migration {version: "1.1", applied: datetime()});
MATCH (n) WHERE EXISTS(n.stix_id) AND NOT EXISTS(n.x_bj_created)
SET n.x_bj_created = datetime();

// V1.2 - Add review status tracking  
CREATE (:Migration {version: "1.2", applied: datetime()});
MATCH (ap:AttackPattern) WHERE NOT EXISTS(ap.x_bj_review_status)
SET ap.x_bj_review_status = "pending";
```

#### **OpenSearch Index Versioning**
```python
def migrate_index_schema(old_version: str, new_version: str):
    """Migrate OpenSearch index to new schema version."""
    
    old_index = f"bandjacks_attack_nodes-{old_version}"
    new_index = f"bandjacks_attack_nodes-{new_version}"
    
    # Create new index with updated mapping
    create_index_with_mapping(new_index, get_mapping_v2())
    
    # Reindex data with transformation
    reindex_with_transform(
        source=old_index,
        dest=new_index,
        transform_script="ctx._source.new_field = 'default_value'"
    )
    
    # Update alias to point to new index
    update_alias("bandjacks_attack_nodes", old_index, new_index)
    
    # Cleanup old index after verification
    delete_index(old_index)
```

### **Schema Validation**

```python
from pydantic import BaseModel, validator

class AttackPatternSchema(BaseModel):
    """Schema validation for Attack Pattern objects."""
    
    stix_id: str
    name: str
    description: str
    external_id: str
    kill_chain_phases: List[str]
    x_mitre_is_subtechnique: bool = False
    
    @validator('stix_id')
    def validate_stix_id(cls, v):
        if not v.startswith('attack-pattern--'):
            raise ValueError('Invalid STIX ID format')
        return v
    
    @validator('external_id')
    def validate_technique_id(cls, v):
        import re
        if not re.match(r'T\d{4}(\.\d{3})?', v):
            raise ValueError('Invalid technique ID format')
        return v
```

## Data Quality & Validation

### **Validation Pipeline**

```python
class DataQualityValidator:
    """Comprehensive data quality validation."""
    
    def validate_extraction_result(self, result: ExtractionResult) -> ValidationReport:
        """Validate extraction result quality."""
        
        report = ValidationReport()
        
        # Check for minimum extraction count
        if len(result.claims) < 3:
            report.add_warning("Low technique extraction count")
        
        # Validate confidence scores
        low_confidence_count = sum(1 for c in result.claims if c.confidence < 50)
        if low_confidence_count > len(result.claims) * 0.3:
            report.add_warning("High number of low-confidence extractions")
        
        # Check for evidence coverage
        for claim in result.claims:
            if not claim.quotes:
                report.add_error(f"Claim {claim.external_id} missing evidence")
            if not claim.line_refs:
                report.add_error(f"Claim {claim.external_id} missing line references")
        
        # Validate technique IDs against ATT&CK
        invalid_techniques = self.validate_technique_ids([c.external_id for c in result.claims])
        for tech_id in invalid_techniques:
            report.add_error(f"Invalid technique ID: {tech_id}")
        
        return report
    
    def validate_graph_consistency(self, session: Session) -> ValidationReport:
        """Validate graph data consistency."""
        
        report = ValidationReport()
        
        # Check for orphaned nodes
        result = session.run("""
            MATCH (n) WHERE NOT (n)--()
            RETURN count(n) as orphan_count, labels(n)[0] as node_type
        """)
        
        for record in result:
            if record["orphan_count"] > 0:
                report.add_warning(f"Found {record['orphan_count']} orphaned {record['node_type']} nodes")
        
        # Check relationship consistency
        result = session.run("""
            MATCH (ap:AttackPattern)-[r:USES]-(is:IntrusionSet)
            WHERE NOT EXISTS(ap.stix_id) OR NOT EXISTS(is.stix_id)
            RETURN count(r) as invalid_relationships
        """)
        
        invalid_count = result.single()["invalid_relationships"]
        if invalid_count > 0:
            report.add_error(f"Found {invalid_count} relationships with missing STIX IDs")
        
        return report
```

### **Data Cleanup Procedures**

```python
def cleanup_extraction_artifacts():
    """Clean up temporary files and stale data."""
    
    # Remove old PDF files
    cleanup_old_files("/tmp/bandjacks/uploads", max_age_days=7)
    
    # Clean up failed extraction jobs
    opensearch.delete_by_query(
        index="bandjacks_reports",
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"status": "failed"}},
                        {"range": {"created": {"lte": "now-30d"}}}
                    ]
                }
            }
        }
    )
    
    # Remove orphaned graph nodes
    neo4j_session.run("""
        MATCH (n) WHERE NOT (n)--() AND n.x_bj_created < datetime() - duration('P30D')
        DELETE n
    """)
```

## Backup & Recovery

### **Backup Strategy**

#### **Neo4j Backup**
```bash
# Full database backup
neo4j-admin database dump --database=neo4j --to-path=/backups/neo4j/

# Incremental backup using APOC
CALL apoc.export.cypher.all("/backups/neo4j/incremental.cypher", {
    format: "cypher-shell",
    useOptimizations: {type: "UNWIND_BATCH", unwindBatchSize: 20}
})

# Point-in-time recovery preparation
neo4j-admin database backup --database=neo4j --backup-dir=/backups/neo4j/continuous/
```

#### **OpenSearch Backup**
```python
# Snapshot repository configuration
PUT /_snapshot/bandjacks_backups
{
    "type": "fs",
    "settings": {
        "location": "/backups/opensearch/snapshots",
        "compress": true
    }
}

# Create snapshot
PUT /_snapshot/bandjacks_backups/snapshot_2024_08_31
{
    "indices": "bandjacks_*",
    "ignore_unavailable": true,
    "include_global_state": false,
    "metadata": {
        "taken_by": "scheduled_backup",
        "taken_because": "daily backup"
    }
}

# Restore from snapshot
POST /_snapshot/bandjacks_backups/snapshot_2024_08_31/_restore
{
    "indices": "bandjacks_attack_nodes-v1,bandjacks_reports",
    "ignore_unavailable": true,
    "include_global_state": false
}
```

### **Disaster Recovery Plan**

1. **Recovery Time Objectives (RTO)**
   - Critical data: 4 hours
   - Full system restoration: 24 hours
   - Acceptable data loss: 1 hour

2. **Recovery Procedures**
   ```bash
   # 1. Restore Neo4j from backup
   neo4j-admin database load --from-path=/backups/neo4j/latest.dump
   
   # 2. Restore OpenSearch indices
   curl -X POST "localhost:9200/_snapshot/bandjacks_backups/latest/_restore"
   
   # 3. Verify data integrity
   python scripts/verify_data_integrity.py
   
   # 4. Restart application services
   systemctl restart bandjacks-api
   systemctl restart bandjacks-ui
   ```

## Performance Optimization

### **Query Optimization**

#### **Neo4j Performance Tuning**
```cypher
// Use parameters to enable query plan caching
MATCH (is:IntrusionSet {name: $actor_name})-[:USES]->(ap:AttackPattern)
WHERE ap.kill_chain_phases CONTAINS $tactic
RETURN ap.external_id, ap.name;

// Optimize with PROFILE to identify bottlenecks
PROFILE MATCH (ae:AttackEpisode)-[:CONTAINS]->(aa:AttackAction)
MATCH (aa)-[:NEXT*1..5]->(next:AttackAction)
WHERE ae.confidence > 0.8
RETURN ae.episode_id, count(next) as chain_length;

// Use indexes effectively
CREATE INDEX episode_confidence FOR (n:AttackEpisode) ON (n.confidence);
```

#### **OpenSearch Performance Tuning**
```json
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "refresh_interval": "30s",
    "index.codec": "best_compression",
    "index.knn": true,
    "index.knn.space_type": "cosinesimil",
    "index.knn.algo_param": {
      "ef_construction": 128,
      "m": 24
    }
  }
}
```

### **Caching Strategy**

```python
class DataCache:
    """Multi-level caching for frequently accessed data."""
    
    def __init__(self):
        self.memory_cache = TTLCache(maxsize=1000, ttl=300)  # 5 minutes
        self.redis_cache = redis.Redis(host='localhost', port=6379, db=0)
    
    async def get_attack_technique(self, technique_id: str) -> Optional[dict]:
        """Get technique with caching."""
        
        # L1 Cache - Memory
        cache_key = f"technique:{technique_id}"
        if cache_key in self.memory_cache:
            return self.memory_cache[cache_key]
        
        # L2 Cache - Redis
        cached_data = self.redis_cache.get(cache_key)
        if cached_data:
            technique = json.loads(cached_data)
            self.memory_cache[cache_key] = technique
            return technique
        
        # L3 - Database
        technique = await self.fetch_from_neo4j(technique_id)
        if technique:
            # Cache for 1 hour
            self.redis_cache.setex(cache_key, 3600, json.dumps(technique))
            self.memory_cache[cache_key] = technique
        
        return technique
```

### **Index Management**

```python
def optimize_opensearch_indices():
    """Optimize OpenSearch indices for better performance."""
    
    # Force merge segments
    opensearch.indices.forcemerge(
        index="bandjacks_*",
        max_num_segments=1,
        wait_for_completion=False
    )
    
    # Update index settings for better search performance
    opensearch.indices.put_settings(
        index="bandjacks_attack_nodes-v1",
        body={
            "settings": {
                "refresh_interval": "30s",
                "number_of_replicas": 0  # Temporarily reduce for reindexing
            }
        }
    )
    
    # Warm up frequently accessed data
    opensearch.indices.warm(index="bandjacks_attack_nodes-v1")
```

## Conclusion

The Bandjacks data architecture successfully balances **performance**, **scalability**, and **standards compliance**. The hybrid storage approach optimizes for different query patterns while maintaining full STIX 2.1 compliance and comprehensive audit trails.

**Key Architectural Strengths:**
- **Standards-Based**: Full STIX 2.1 and ADM compliance
- **Evidence-Driven**: Complete provenance tracking  
- **Performance-Optimized**: Multi-level caching and query optimization
- **Scalable Design**: Horizontal scaling capabilities
- **Data Quality**: Comprehensive validation and cleanup procedures

The system provides a robust foundation for **enterprise-scale threat intelligence operations** while maintaining the flexibility needed for **ongoing research and development**.