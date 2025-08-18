#!/usr/bin/env python3
"""Analyze D3FEND OWL structure to implement full production extraction."""

import sys
from rdflib import Graph, Namespace, RDF, RDFS, OWL, URIRef, Literal
from collections import defaultdict

def analyze_d3fend_owl():
    """Analyze the D3FEND OWL structure to understand how to extract all techniques."""
    print("\n" + "="*80)
    print("D3FEND OWL STRUCTURE ANALYSIS")
    print("="*80)
    
    # Load the OWL
    print("\n1. Loading D3FEND OWL from https://d3fend.mitre.org/ontologies/d3fend.owl")
    g = Graph()
    try:
        g.parse("https://d3fend.mitre.org/ontologies/d3fend.owl", format="xml")
        print(f"✓ Loaded graph with {len(g)} triples")
    except Exception as e:
        print(f"✗ Failed to load OWL: {e}")
        return
    
    # Define namespaces
    D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
    SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")
    
    # 2. Analyze all classes in the ontology
    print("\n2. Analyzing OWL Classes")
    print("-" * 40)
    
    classes = set()
    for s, p, o in g.triples((None, RDF.type, OWL.Class)):
        if str(s).startswith("http://d3fend.mitre.org"):
            classes.add(s)
    
    print(f"Found {len(classes)} D3FEND classes")
    
    # Sample some classes
    sample_classes = list(classes)[:10]
    print("\nSample classes:")
    for cls in sample_classes:
        local_name = str(cls).split('#')[-1]
        print(f"  - {local_name}")
    
    # 3. Find defensive technique classes specifically
    print("\n3. Finding Defensive Technique Classes")
    print("-" * 40)
    
    # Look for classes with "Technique" in name or specific patterns
    technique_classes = []
    defense_classes = []
    
    for cls in classes:
        local_name = str(cls).split('#')[-1]
        
        # Check various patterns
        if 'Technique' in local_name:
            technique_classes.append(cls)
        if 'Defense' in local_name or 'Defensive' in local_name:
            defense_classes.append(cls)
    
    print(f"Found {len(technique_classes)} classes with 'Technique' in name")
    print(f"Found {len(defense_classes)} classes with 'Defense' in name")
    
    # 4. Analyze subclass hierarchies
    print("\n4. Analyzing Subclass Hierarchies")
    print("-" * 40)
    
    # Find top-level defensive technique class
    defensive_technique_class = None
    for cls in classes:
        local_name = str(cls).split('#')[-1]
        if local_name == "DefensiveTechnique" or local_name == "d3fend-technique":
            defensive_technique_class = cls
            print(f"Found main defensive technique class: {local_name}")
            break
    
    # Find all subclasses of DefensiveTechnique
    if defensive_technique_class:
        subclasses = set()
        for s, p, o in g.triples((None, RDFS.subClassOf, defensive_technique_class)):
            subclasses.add(s)
        
        # Also find transitive subclasses
        def get_all_subclasses(parent, visited=None):
            if visited is None:
                visited = set()
            if parent in visited:
                return set()
            visited.add(parent)
            
            direct_subclasses = set()
            for s, p, o in g.triples((None, RDFS.subClassOf, parent)):
                direct_subclasses.add(s)
                # Recursively get subclasses
                direct_subclasses.update(get_all_subclasses(s, visited))
            return direct_subclasses
        
        all_subclasses = get_all_subclasses(defensive_technique_class)
        print(f"Found {len(all_subclasses)} total subclasses of DefensiveTechnique")
        
        # Sample some
        sample_subs = list(all_subclasses)[:20]
        print("\nSample defensive techniques:")
        for sub in sample_subs:
            local_name = str(sub).split('#')[-1]
            
            # Get label
            label = None
            for p in [RDFS.label, D3F['d3fend-label'], SKOS.prefLabel]:
                labels = list(g.objects(sub, p))
                if labels:
                    label = str(labels[0])
                    break
            
            print(f"  - {local_name}: {label or 'No label'}")
    
    # 5. Analyze properties used for techniques
    print("\n5. Analyzing Properties Used")
    print("-" * 40)
    
    # Find all properties used with technique classes
    properties_used = defaultdict(int)
    
    for cls in list(technique_classes)[:10] + list(all_subclasses if defensive_technique_class else [])[:10]:
        for s, p, o in g.triples((cls, None, None)):
            prop_name = str(p).split('#')[-1].split('/')[-1]
            properties_used[prop_name] += 1
    
    print("Common properties on technique classes:")
    for prop, count in sorted(properties_used.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"  - {prop}: {count} uses")
    
    # 6. Look for D3FEND-specific annotations
    print("\n6. Analyzing D3FEND-specific Annotations")
    print("-" * 40)
    
    # Check for d3fend-specific predicates
    d3fend_predicates = set()
    for s, p, o in g:
        if "d3fend" in str(p).lower():
            d3fend_predicates.add(p)
    
    print(f"Found {len(d3fend_predicates)} D3FEND-specific predicates")
    for pred in list(d3fend_predicates)[:10]:
        print(f"  - {pred}")
    
    # 7. Extract a complete technique example
    print("\n7. Complete Technique Example")
    print("-" * 40)
    
    # Find a well-defined technique
    example_technique = None
    for cls in classes:
        local_name = str(cls).split('#')[-1]
        if "NetworkTrafficFiltering" in local_name or "FileEncryption" in local_name:
            example_technique = cls
            break
    
    if example_technique:
        print(f"Example technique: {str(example_technique).split('#')[-1]}")
        print("\nAll properties:")
        for s, p, o in g.triples((example_technique, None, None)):
            prop = str(p).split('#')[-1].split('/')[-1]
            if isinstance(o, Literal):
                value = str(o)[:100] + "..." if len(str(o)) > 100 else str(o)
            else:
                value = str(o).split('#')[-1].split('/')[-1]
            print(f"  {prop}: {value}")
    
    # 8. Find actual defensive techniques using multiple strategies
    print("\n8. Extracting All Defensive Techniques")
    print("-" * 40)
    
    all_techniques = set()
    
    # Strategy 1: Find all subclasses of DefensiveTechnique
    if defensive_technique_class:
        all_techniques.update(all_subclasses)
    
    # Strategy 2: Find classes with d3fend:definition
    for s, p, o in g.triples((None, D3F['d3fend-kb-article'], None)):
        if isinstance(s, URIRef) and str(s).startswith("http://d3fend.mitre.org"):
            all_techniques.add(s)
    
    # Strategy 3: Find classes with defensive labels
    defensive_keywords = ['Block', 'Filter', 'Isolate', 'Encrypt', 'Monitor', 'Detect', 'Prevent', 'Analyze', 'Authenticate', 'Audit']
    for cls in classes:
        for p in [RDFS.label, D3F['d3fend-label']]:
            labels = list(g.objects(cls, p))
            for label in labels:
                if any(keyword in str(label) for keyword in defensive_keywords):
                    all_techniques.add(cls)
                    break
    
    print(f"Total defensive techniques found: {len(all_techniques)}")
    
    # Extract details for first 5 techniques
    print("\nDetailed extraction for sample techniques:")
    for tech in list(all_techniques)[:5]:
        local_name = str(tech).split('#')[-1]
        
        # Get label
        label = None
        for p in [RDFS.label, D3F['d3fend-label'], SKOS.prefLabel]:
            labels = list(g.objects(tech, p))
            if labels:
                label = str(labels[0])
                break
        
        # Get definition
        definition = None
        for p in [D3F['d3fend-kb-article'], D3F['definition'], SKOS.definition]:
            defs = list(g.objects(tech, p))
            if defs:
                definition = str(defs[0])[:100] + "..."
                break
        
        # Get parent/category
        parent = None
        for s, p, o in g.triples((tech, RDFS.subClassOf, None)):
            if str(o).startswith("http://d3fend.mitre.org"):
                parent = str(o).split('#')[-1]
                break
        
        print(f"\n  {local_name}:")
        print(f"    Label: {label or 'None'}")
        print(f"    Definition: {definition or 'None'}")
        print(f"    Parent: {parent or 'None'}")
    
    return all_techniques


if __name__ == "__main__":
    techniques = analyze_d3fend_owl()