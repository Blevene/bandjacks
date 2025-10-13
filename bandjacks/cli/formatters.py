"""Output formatters for CLI analytics and reports."""

import csv
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class AnalyticsFormatter:
    """Format analytics results for various output formats."""

    @staticmethod
    def export_cooccurrence_csv(
        metrics: List[Any],
        output_path: Path,
        technique_names: Optional[Dict[str, str]] = None
    ):
        """
        Export co-occurrence metrics to CSV.

        Args:
            metrics: List of CooccurrenceMetrics objects
            output_path: Output file path
            technique_names: Optional mapping of technique IDs to names
        """
        technique_names = technique_names or {}

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Technique_A',
                'Name_A',
                'Technique_B',
                'Name_B',
                'Co-occurrence_Count',
                'Episodes_with_A',
                'Episodes_with_B',
                'Total_Episodes',
                'Confidence_A_to_B',
                'Confidence_B_to_A',
                'Lift',
                'PMI',
                'NPMI',
                'Jaccard'
            ])

            # Data rows
            for m in metrics:
                writer.writerow([
                    m.technique_a,
                    technique_names.get(m.technique_a, ''),
                    m.technique_b,
                    technique_names.get(m.technique_b, ''),
                    m.count,
                    m.support_a,
                    m.support_b,
                    m.total_episodes,
                    f"{m.confidence_a_to_b:.4f}",
                    f"{m.confidence_b_to_a:.4f}",
                    f"{m.lift:.4f}",
                    f"{m.pmi:.4f}",
                    f"{m.npmi:.4f}",
                    f"{m.jaccard:.4f}"
                ])

    @staticmethod
    def export_cooccurrence_json(
        metrics: List[Any],
        output_path: Path,
        technique_names: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Export co-occurrence metrics to JSON.

        Args:
            metrics: List of CooccurrenceMetrics objects
            output_path: Output file path
            technique_names: Optional mapping of technique IDs to names
            metadata: Optional metadata to include
        """
        technique_names = technique_names or {}

        data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_pairs": len(metrics),
                **(metadata or {})
            },
            "metrics": [
                {
                    "technique_a": {
                        "id": m.technique_a,
                        "name": technique_names.get(m.technique_a, "Unknown")
                    },
                    "technique_b": {
                        "id": m.technique_b,
                        "name": technique_names.get(m.technique_b, "Unknown")
                    },
                    "statistics": {
                        "co_occurrence_count": m.count,
                        "episodes_with_a": m.support_a,
                        "episodes_with_b": m.support_b,
                        "total_episodes": m.total_episodes
                    },
                    "metrics": {
                        "confidence_a_to_b": round(m.confidence_a_to_b, 4),
                        "confidence_b_to_a": round(m.confidence_b_to_a, 4),
                        "lift": round(m.lift, 4),
                        "pmi": round(m.pmi, 4),
                        "npmi": round(m.npmi, 4),
                        "jaccard": round(m.jaccard, 4)
                    }
                }
                for m in metrics
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_bundles_csv(
        bundles: List[Any],
        output_path: Path
    ):
        """
        Export technique bundles to CSV.

        Args:
            bundles: List of TechniqueBundle objects
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Techniques',
                'Technique_Count',
                'Support',
                'Confidence',
                'Lift',
                'Tactics',
                'Intrusion_Sets'
            ])

            # Data rows
            for bundle in bundles:
                writer.writerow([
                    ', '.join(bundle.techniques),
                    len(bundle.techniques),
                    bundle.support,
                    f"{bundle.confidence:.4f}",
                    f"{bundle.lift:.4f}",
                    ', '.join(bundle.tactics),
                    ', '.join(bundle.intrusion_sets)
                ])

    @staticmethod
    def export_bundles_json(
        bundles: List[Any],
        output_path: Path,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Export technique bundles to JSON.

        Args:
            bundles: List of TechniqueBundle objects
            output_path: Output file path
            metadata: Optional metadata
        """
        data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_bundles": len(bundles),
                **(metadata or {})
            },
            "bundles": [
                {
                    "techniques": bundle.techniques,
                    "technique_count": len(bundle.techniques),
                    "support": bundle.support,
                    "confidence": round(bundle.confidence, 4),
                    "lift": round(bundle.lift, 4),
                    "tactics": bundle.tactics,
                    "intrusion_sets": bundle.intrusion_sets
                }
                for bundle in bundles
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_actor_profiles_csv(
        profiles: List[Any],
        output_path: Path
    ):
        """
        Export actor profiles to CSV.

        Args:
            profiles: List of ActorProfile objects
            output_path: Output file path
        """
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Intrusion_Set_ID',
                'Name',
                'Total_Episodes',
                'Unique_Techniques',
                'Dominant_Tactics',
                'Top_5_Signature_Techniques'
            ])

            # Data rows
            for profile in profiles:
                writer.writerow([
                    profile.intrusion_set_id,
                    profile.intrusion_set_name,
                    profile.total_episodes,
                    len(profile.techniques),
                    ', '.join(profile.dominant_tactics),
                    ', '.join(profile.signature_techniques[:5])
                ])

    @staticmethod
    def export_actor_profiles_json(
        profiles: List[Any],
        output_path: Path,
        include_tf_idf: bool = False
    ):
        """
        Export actor profiles to JSON.

        Args:
            profiles: List of ActorProfile objects
            output_path: Output file path
            include_tf_idf: Whether to include TF-IDF vectors
        """
        data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_actors": len(profiles)
            },
            "profiles": []
        }

        for profile in profiles:
            profile_data = {
                "intrusion_set_id": profile.intrusion_set_id,
                "intrusion_set_name": profile.intrusion_set_name,
                "statistics": {
                    "total_episodes": profile.total_episodes,
                    "unique_techniques": len(profile.techniques)
                },
                "techniques": profile.techniques,
                "technique_counts": profile.technique_counts,
                "dominant_tactics": profile.dominant_tactics,
                "signature_techniques": profile.signature_techniques
            }

            if include_tf_idf and profile.tf_idf_vector is not None:
                profile_data["tf_idf_vector"] = profile.tf_idf_vector.tolist()

            data["profiles"].append(profile_data)

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_markdown_report(
        output_path: Path,
        sections: Dict[str, Any]
    ):
        """
        Generate a comprehensive markdown report.

        Args:
            output_path: Output file path
            sections: Dict of section_name -> section_data
        """
        with open(output_path, 'w') as f:
            # Title
            f.write("# Bandjacks Analytics Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            f.write("---\n\n")

            # Write each section
            for section_name, section_data in sections.items():
                f.write(f"## {section_name}\n\n")

                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        f.write(f"- **{key}**: {value}\n")
                    f.write("\n")
                elif isinstance(section_data, list):
                    for item in section_data:
                        if isinstance(item, str):
                            f.write(f"- {item}\n")
                        else:
                            f.write(f"- {item}\n")
                    f.write("\n")
                elif isinstance(section_data, str):
                    f.write(f"{section_data}\n\n")
