#!/usr/bin/env python3
"""
Test script for new CLI enhancements: batch extraction, Neo4j storage, and analytics export.

This test validates:
1. Batch extraction with Neo4j storage
2. Analytics export to CSV/JSON
3. Workflow commands
"""

import os
import sys
import tempfile
import subprocess
from pathlib import Path
import json
import csv
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from neo4j import GraphDatabase


class CLIEnhancementTester:
    """Test harness for CLI enhancements."""

    def __init__(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="bandjacks_cli_test_"))
        self.reports_dir = self.test_dir / "reports"
        self.output_dir = self.test_dir / "output"
        self.reports_dir.mkdir()
        self.output_dir.mkdir()

        # Get Neo4j connection from environment
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD", "")

        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "test_dir": str(self.test_dir),
            "tests_passed": 0,
            "tests_failed": 0,
            "errors": []
        }

    def log(self, message, level="INFO"):
        """Log a message."""
        prefix = {
            "INFO": "ℹ️ ",
            "SUCCESS": "✅",
            "ERROR": "❌",
            "WARN": "⚠️ "
        }.get(level, "  ")
        print(f"{prefix} {message}")

    def create_sample_reports(self):
        """Create sample threat reports for testing."""
        self.log("Creating sample threat reports...")

        reports = [
            {
                "filename": "apt29_report.txt",
                "content": """
APT29 Threat Intelligence Report

Overview:
APT29, also known as Cozy Bear, is a sophisticated threat actor attributed to Russian intelligence.

Techniques Observed:
- T1566.001 (Spearphishing Attachment): The group used malicious PDF attachments
- T1059.001 (PowerShell): PowerShell scripts were used for execution
- T1055 (Process Injection): Malware injected into legitimate processes
- T1071.001 (Web Protocols): C2 communications over HTTPS
- T1027 (Obfuscated Files): Heavy use of code obfuscation
- T1003.001 (LSASS Memory): Credential dumping from LSASS

The campaign began with spearphishing emails containing malicious attachments.
Once opened, PowerShell scripts executed to establish persistence.
The malware then injected itself into legitimate processes and established
command and control over HTTPS.
                """
            },
            {
                "filename": "lazarus_report.txt",
                "content": """
Lazarus Group Campaign Analysis

Executive Summary:
Lazarus Group conducted a sophisticated supply chain attack targeting financial institutions.

Attack Flow:
1. Initial Access via T1195.002 (Compromise Software Supply Chain)
2. Execution through T1059.003 (Windows Command Shell)
3. Persistence via T1053.005 (Scheduled Task)
4. Credential Access using T1003.001 (LSASS Memory)
5. Lateral Movement with T1021.001 (Remote Desktop Protocol)
6. Collection via T1005 (Data from Local System)
7. Exfiltration over T1041 (Exfiltration Over C2 Channel)

The attack demonstrated advanced capabilities including supply chain compromise
and multi-stage malware deployment.
                """
            },
            {
                "filename": "emotet_report.txt",
                "content": """
Emotet Malware Distribution Campaign

Overview:
Emotet continues to be a major threat, distributed through spam campaigns.

Observed TTPs:
- T1566.001 (Spearphishing Attachment): Malicious Office documents
- T1204.002 (Malicious File): Users enabled macros
- T1059.005 (Visual Basic): VBA macros for initial execution
- T1105 (Ingress Tool Transfer): Downloaded additional payloads
- T1055 (Process Injection): Injected into system processes
- T1071.001 (Web Protocols): HTTP-based C2 communication

The campaign used document macros to download and execute Emotet,
which then established persistence and downloaded additional malware.
                """
            }
        ]

        for report in reports:
            report_path = self.reports_dir / report["filename"]
            with open(report_path, 'w') as f:
                f.write(report["content"])

        self.log(f"Created {len(reports)} sample reports in {self.reports_dir}", "SUCCESS")
        return len(reports)

    def test_batch_extraction_with_neo4j(self):
        """Test batch extraction with Neo4j storage."""
        self.log("\n=== Testing Batch Extraction with Neo4j Storage ===")

        try:
            # Run batch extraction with Neo4j storage
            cmd = [
                sys.executable, "-m", "bandjacks.cli.batch_extract",
                str(self.reports_dir),
                "--store-in-neo4j",
                "--neo4j-uri", self.neo4j_uri,
                "--neo4j-user", self.neo4j_user,
                "--neo4j-password", self.neo4j_password,
                "--workers", "2",
                "--chunk-size", "2000",
                "--max-chunks", "5"
            ]

            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.log(f"Batch extraction failed: {result.stderr}", "ERROR")
                self.results["errors"].append({
                    "test": "batch_extraction_neo4j",
                    "error": result.stderr
                })
                self.results["tests_failed"] += 1
                return False

            # Verify Neo4j nodes were created
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )

            with driver.session() as session:
                # Count AttackEpisode nodes created in this test
                result = session.run("""
                    MATCH (e:AttackEpisode)
                    WHERE e.source_file CONTAINS 'apt29' OR
                          e.source_file CONTAINS 'lazarus' OR
                          e.source_file CONTAINS 'emotet'
                    RETURN count(e) as count
                """)
                episode_count = result.single()["count"]

                # Count AttackAction nodes
                result = session.run("""
                    MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
                    WHERE e.source_file CONTAINS 'apt29' OR
                          e.source_file CONTAINS 'lazarus' OR
                          e.source_file CONTAINS 'emotet'
                    RETURN count(a) as count
                """)
                action_count = result.single()["count"]

            driver.close()

            self.log(f"Created {episode_count} AttackEpisode nodes", "SUCCESS")
            self.log(f"Created {action_count} AttackAction nodes", "SUCCESS")

            if episode_count > 0 and action_count > 0:
                self.results["tests_passed"] += 1
                return True
            else:
                self.log("No nodes created in Neo4j", "ERROR")
                self.results["tests_failed"] += 1
                return False

        except Exception as e:
            self.log(f"Test failed with exception: {e}", "ERROR")
            self.results["errors"].append({
                "test": "batch_extraction_neo4j",
                "error": str(e)
            })
            self.results["tests_failed"] += 1
            return False

    def test_analytics_export_csv(self):
        """Test analytics export to CSV."""
        self.log("\n=== Testing Analytics Export to CSV ===")

        try:
            output_file = self.output_dir / "test_cooccurrence.csv"

            cmd = [
                sys.executable, "-m", "bandjacks.cli.main",
                "analytics", "global",
                "--format", "csv",
                "--output", str(output_file),
                "--limit", "10"
            ]

            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.log(f"Analytics export failed: {result.stderr}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Verify CSV file was created and has content
            if not output_file.exists():
                self.log(f"Output file not created: {output_file}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Read and validate CSV
            with open(output_file, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.log(f"CSV file created with {len(rows)} rows", "SUCCESS")

            # Validate CSV structure
            if rows:
                expected_columns = ['Technique_A', 'Technique_B', 'Co-occurrence_Count', 'NPMI', 'Lift']
                missing_cols = [col for col in expected_columns if col not in rows[0].keys()]

                if missing_cols:
                    self.log(f"Missing columns in CSV: {missing_cols}", "ERROR")
                    self.results["tests_failed"] += 1
                    return False

            self.results["tests_passed"] += 1
            return True

        except Exception as e:
            self.log(f"Test failed with exception: {e}", "ERROR")
            self.results["errors"].append({
                "test": "analytics_export_csv",
                "error": str(e)
            })
            self.results["tests_failed"] += 1
            return False

    def test_analytics_export_json(self):
        """Test analytics export to JSON."""
        self.log("\n=== Testing Analytics Export to JSON ===")

        try:
            output_file = self.output_dir / "test_cooccurrence.json"

            cmd = [
                sys.executable, "-m", "bandjacks.cli.main",
                "analytics", "global",
                "--format", "json",
                "--output", str(output_file),
                "--limit", "10"
            ]

            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.log(f"Analytics export failed: {result.stderr}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Verify JSON file was created
            if not output_file.exists():
                self.log(f"Output file not created: {output_file}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Read and validate JSON
            with open(output_file, 'r') as f:
                data = json.load(f)

            # Validate JSON structure
            if "metadata" not in data or "metrics" not in data:
                self.log("Invalid JSON structure", "ERROR")
                self.results["tests_failed"] += 1
                return False

            self.log(f"JSON file created with {len(data.get('metrics', []))} metrics", "SUCCESS")
            self.log(f"Metadata: {data.get('metadata', {}).get('analysis_type', 'unknown')}", "SUCCESS")

            self.results["tests_passed"] += 1
            return True

        except Exception as e:
            self.log(f"Test failed with exception: {e}", "ERROR")
            self.results["errors"].append({
                "test": "analytics_export_json",
                "error": str(e)
            })
            self.results["tests_failed"] += 1
            return False

    def test_bundles_export(self):
        """Test technique bundles export."""
        self.log("\n=== Testing Technique Bundles Export ===")

        try:
            output_file = self.output_dir / "test_bundles.json"

            cmd = [
                sys.executable, "-m", "bandjacks.cli.main",
                "analytics", "bundles",
                "--format", "json",
                "--output", str(output_file),
                "--min-support", "2"
            ]

            self.log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.log(f"Bundles export failed: {result.stderr}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Verify JSON file was created
            if not output_file.exists():
                self.log(f"Output file not created: {output_file}", "ERROR")
                self.results["tests_failed"] += 1
                return False

            # Read and validate JSON
            with open(output_file, 'r') as f:
                data = json.load(f)

            bundles_count = len(data.get('bundles', []))
            self.log(f"Exported {bundles_count} technique bundles", "SUCCESS")

            self.results["tests_passed"] += 1
            return True

        except Exception as e:
            self.log(f"Test failed with exception: {e}", "ERROR")
            self.results["errors"].append({
                "test": "bundles_export",
                "error": str(e)
            })
            self.results["tests_failed"] += 1
            return False

    def cleanup_neo4j_test_data(self):
        """Clean up test data from Neo4j."""
        self.log("\n=== Cleaning up test data from Neo4j ===")

        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )

            with driver.session() as session:
                # Delete test AttackEpisodes and their AttackActions
                result = session.run("""
                    MATCH (e:AttackEpisode)
                    WHERE e.source_file CONTAINS 'apt29' OR
                          e.source_file CONTAINS 'lazarus' OR
                          e.source_file CONTAINS 'emotet'
                    MATCH (e)-[:CONTAINS]->(a:AttackAction)
                    DETACH DELETE e, a
                    RETURN count(e) as deleted
                """)

                deleted_count = result.single()["deleted"]

            driver.close()

            self.log(f"Deleted {deleted_count} test episodes from Neo4j", "SUCCESS")

        except Exception as e:
            self.log(f"Cleanup failed: {e}", "WARN")

    def print_summary(self):
        """Print test summary."""
        self.log("\n" + "=" * 60)
        self.log("TEST SUMMARY", "INFO")
        self.log("=" * 60)
        self.log(f"Tests Passed: {self.results['tests_passed']}", "SUCCESS")
        self.log(f"Tests Failed: {self.results['tests_failed']}", "ERROR" if self.results['tests_failed'] > 0 else "INFO")
        self.log(f"Test Directory: {self.results['test_dir']}", "INFO")

        if self.results['errors']:
            self.log("\nErrors:", "ERROR")
            for error in self.results['errors']:
                self.log(f"  {error['test']}: {error['error']}", "ERROR")

        self.log("\nOutput Files:", "INFO")
        for file in self.output_dir.glob("*"):
            file_size = file.stat().st_size
            self.log(f"  {file.name} ({file_size} bytes)", "SUCCESS")

        self.log("=" * 60)

        # Save results to JSON
        results_file = self.test_dir / "test_results.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        self.log(f"\nFull results saved to: {results_file}", "INFO")

    def run_all_tests(self):
        """Run all tests."""
        self.log("Starting CLI Enhancement Tests...")
        self.log(f"Test directory: {self.test_dir}")

        # Create sample data
        self.create_sample_reports()

        # Run tests
        self.test_batch_extraction_with_neo4j()
        self.test_analytics_export_csv()
        self.test_analytics_export_json()
        self.test_bundles_export()

        # Cleanup
        self.cleanup_neo4j_test_data()

        # Print summary
        self.print_summary()

        return self.results['tests_failed'] == 0


def main():
    """Main entry point."""
    tester = CLIEnhancementTester()
    success = tester.run_all_tests()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
