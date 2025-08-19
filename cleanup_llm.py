#!/usr/bin/env python3
"""Clean up unused code in the llm folder."""

import os
import shutil
from pathlib import Path

# Files that ARE actively used in production
KEEP_FILES = {
    "__init__.py",           # Package init
    "client.py",             # LLM client wrapper
    "extractor.py",          # Main LLM extractor (legacy)
    "prompts.py",            # Prompts for extraction
    "schemas.py",            # Schema definitions
    "tools.py",              # Tool adapters for LLM
    "stix_builder.py",       # STIX bundle builder
    "entity_resolver.py",    # Entity resolution
    "provenance_tracker.py", # Provenance tracking
    "flow_builder.py",       # Attack flow builder
    "flows.py",              # Flow synthesis
    "opportunities.py",      # Opportunity analysis
    
    # New agentic v2 pipeline
    "agentic_v2.py",         # Agentic v2 orchestrator
    "agents_v2.py",          # Agentic v2 agents
    "memory.py",             # Working memory for agents
    "bundle_validator.py",   # Bundle validation
}

# Files to REMOVE (unused or experimental)
REMOVE_FILES = {
    "confidence_scorer.py",  # Not used anywhere
    "stix_converter.py",     # Not used anywhere
    "adk_agents.py",         # ADK shells not integrated yet
}

def cleanup_llm_folder():
    """Clean up the llm folder by removing unused files."""
    
    llm_dir = Path("/Volumes/tank/bandjacks/bandjacks/llm")
    
    print("LLM Folder Cleanup")
    print("=" * 60)
    
    # List all Python files
    all_files = set(f.name for f in llm_dir.glob("*.py"))
    
    print(f"\nFound {len(all_files)} Python files in llm folder")
    
    # Identify files to remove
    files_to_remove = REMOVE_FILES
    
    # Also identify any files not in KEEP_FILES or REMOVE_FILES
    unknown_files = all_files - KEEP_FILES - REMOVE_FILES
    
    if unknown_files:
        print(f"\n⚠️  Unknown files found (not in keep or remove list):")
        for f in sorted(unknown_files):
            print(f"  • {f}")
        print("\nThese files need manual review.")
    
    # Remove identified unused files
    if files_to_remove:
        print(f"\n🗑️  Removing {len(files_to_remove)} unused files:")
        for filename in sorted(files_to_remove):
            filepath = llm_dir / filename
            if filepath.exists():
                print(f"  • Removing {filename}")
                # Create backup first
                backup_dir = llm_dir / "experimental" / "removed_files"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_path = backup_dir / filename
                shutil.move(str(filepath), str(backup_path))
                print(f"    → Moved to experimental/removed_files/{filename}")
            else:
                print(f"  • {filename} not found (already removed?)")
    
    # Report on experimental folder
    experimental_dir = llm_dir / "experimental"
    if experimental_dir.exists():
        exp_files = list(experimental_dir.glob("*.py"))
        print(f"\n📁 Experimental folder contains {len(exp_files)} files")
        print("   These are preserved for reference but not used in production.")
    
    # Summary of kept files
    print(f"\n✅ Keeping {len(KEEP_FILES)} production files:")
    categories = {
        "Core extraction": ["extractor.py", "prompts.py", "schemas.py", "client.py"],
        "Agentic v2": ["agentic_v2.py", "agents_v2.py", "memory.py"],
        "STIX/Graph": ["stix_builder.py", "entity_resolver.py", "provenance_tracker.py", "bundle_validator.py"],
        "Flows": ["flow_builder.py", "flows.py", "opportunities.py"],
        "Tools": ["tools.py"],
        "Package": ["__init__.py"],
    }
    
    for category, files in categories.items():
        print(f"\n  {category}:")
        for f in files:
            if f in KEEP_FILES:
                status = "✓" if (llm_dir / f).exists() else "✗"
                print(f"    {status} {f}")
    
    print("\n" + "=" * 60)
    print("Cleanup complete!")
    
    # Final file count
    remaining_files = list(llm_dir.glob("*.py"))
    print(f"\nFinal state: {len(remaining_files)} Python files in llm folder")
    print(f"Reduced from {len(all_files)} to {len(remaining_files)} files")
    print(f"Space saved by moving {len(files_to_remove)} unused files")


if __name__ == "__main__":
    cleanup_llm_folder()