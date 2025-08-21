"""D3FEND coverage verification for common attack techniques."""

import logging
from typing import Dict, List, Any
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class D3FENDVerifier:
    """Verify D3FEND defense coverage for critical techniques."""
    
    # Common techniques that MUST have defensive coverage
    CRITICAL_TECHNIQUES = [
        "T1059",  # Command and Scripting Interpreter
        "T1110",  # Brute Force
        "T1003",  # OS Credential Dumping
        "T1055",  # Process Injection
        "T1071",  # Application Layer Protocol
        "T1566",  # Phishing
        "T1053",  # Scheduled Task/Job
        "T1078",  # Valid Accounts
        "T1486",  # Data Encrypted for Impact
        "T1490"   # Inhibit System Recovery
    ]
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize verifier with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def verify_defense_coverage(self) -> Dict[str, Any]:
        """
        Verify that common attack techniques have D3FEND counters.
        
        Returns:
            Verification report with coverage statistics
        """
        with self.driver.session() as session:
            coverage_report = {
                "checked_techniques": [],
                "covered_techniques": [],
                "uncovered_techniques": [],
                "total_counters": 0,
                "verification_passed": True,
                "errors": []
            }
            
            for technique_id in self.CRITICAL_TECHNIQUES:
                # Check if technique exists and has COUNTERS
                query = """
                    MATCH (t:AttackPattern)
                    WHERE t.external_id = $technique_id OR t.external_id STARTS WITH ($technique_id + '.')
                    OPTIONAL MATCH (d:D3fendTechnique)-[c:COUNTERS]->(t)
                    RETURN t.external_id as technique_id,
                           t.name as technique_name,
                           count(DISTINCT d) as counter_count,
                           collect(DISTINCT d.name)[..3] as sample_defenses
                """
                
                result = session.run(query, technique_id=technique_id)
                records = list(result)
                
                if not records:
                    coverage_report["errors"].append(f"Technique {technique_id} not found in database")
                    coverage_report["verification_passed"] = False
                    continue
                
                for record in records:
                    tech_id = record["technique_id"]
                    tech_name = record["technique_name"]
                    counter_count = record["counter_count"]
                    sample_defenses = record["sample_defenses"]
                    
                    coverage_report["checked_techniques"].append({
                        "id": tech_id,
                        "name": tech_name,
                        "counter_count": counter_count,
                        "sample_defenses": sample_defenses
                    })
                    
                    if counter_count > 0:
                        coverage_report["covered_techniques"].append(tech_id)
                        coverage_report["total_counters"] += counter_count
                    else:
                        coverage_report["uncovered_techniques"].append(tech_id)
                        coverage_report["errors"].append(
                            f"CRITICAL: Technique {tech_id} ({tech_name}) has NO defensive counters"
                        )
                        coverage_report["verification_passed"] = False
            
            # Calculate coverage percentage
            total_checked = len(coverage_report["checked_techniques"])
            total_covered = len(coverage_report["covered_techniques"])
            coverage_report["coverage_percentage"] = (
                (total_covered / total_checked * 100) if total_checked > 0 else 0
            )
            
            # Log results
            if coverage_report["verification_passed"]:
                logger.info(
                    f"D3FEND verification PASSED: {total_covered}/{total_checked} techniques have counters "
                    f"({coverage_report['coverage_percentage']:.1f}% coverage)"
                )
            else:
                logger.error(
                    f"D3FEND verification FAILED: {len(coverage_report['uncovered_techniques'])} critical "
                    f"techniques lack defensive counters"
                )
                for error in coverage_report["errors"]:
                    logger.error(f"  - {error}")
            
            return coverage_report
    
    def verify_overlay_quality(self, min_counters_per_technique: int = 2) -> Dict[str, Any]:
        """
        Verify quality of D3FEND overlay (average counters per technique).
        
        Args:
            min_counters_per_technique: Minimum expected counters per technique
            
        Returns:
            Quality report with statistics
        """
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern)
                WHERE NOT t.revoked AND NOT t.x_mitre_deprecated
                OPTIONAL MATCH (d:D3fendTechnique)-[:COUNTERS]->(t)
                WITH t, count(DISTINCT d) as counter_count
                RETURN avg(counter_count) as avg_counters,
                       min(counter_count) as min_counters,
                       max(counter_count) as max_counters,
                       count(CASE WHEN counter_count >= $min_required THEN 1 END) as adequate_coverage,
                       count(t) as total_techniques
            """
            
            result = session.run(query, min_required=min_counters_per_technique).single()
            
            quality_report = {
                "avg_counters_per_technique": round(result["avg_counters"], 2),
                "min_counters": result["min_counters"],
                "max_counters": result["max_counters"],
                "techniques_with_adequate_coverage": result["adequate_coverage"],
                "total_techniques": result["total_techniques"],
                "adequacy_percentage": round(
                    result["adequate_coverage"] / result["total_techniques"] * 100, 2
                ) if result["total_techniques"] > 0 else 0,
                "quality_passed": result["avg_counters"] >= min_counters_per_technique
            }
            
            if quality_report["quality_passed"]:
                logger.info(
                    f"D3FEND quality check PASSED: Average {quality_report['avg_counters_per_technique']} "
                    f"counters per technique (minimum: {min_counters_per_technique})"
                )
            else:
                logger.warning(
                    f"D3FEND quality check FAILED: Average {quality_report['avg_counters_per_technique']} "
                    f"counters per technique (minimum: {min_counters_per_technique})"
                )
            
            return quality_report
    
    def run_full_verification(self) -> Dict[str, Any]:
        """
        Run complete D3FEND verification suite.
        
        Returns:
            Complete verification report
        """
        logger.info("Starting D3FEND verification...")
        
        # Run coverage verification
        coverage_report = self.verify_defense_coverage()
        
        # Run quality verification
        quality_report = self.verify_overlay_quality()
        
        # Combine reports
        full_report = {
            "coverage": coverage_report,
            "quality": quality_report,
            "overall_passed": coverage_report["verification_passed"] and quality_report["quality_passed"],
            "summary": {
                "critical_techniques_covered": f"{len(coverage_report['covered_techniques'])}/{len(self.CRITICAL_TECHNIQUES)}",
                "coverage_percentage": coverage_report["coverage_percentage"],
                "avg_counters": quality_report["avg_counters_per_technique"],
                "adequacy_percentage": quality_report["adequacy_percentage"]
            }
        }
        
        logger.info(f"D3FEND verification complete. Overall result: {'PASSED' if full_report['overall_passed'] else 'FAILED'}")
        
        return full_report
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


def verify_d3fend_after_load(neo4j_uri: str, neo4j_user: str, neo4j_password: str) -> bool:
    """
    Convenience function to verify D3FEND after ATT&CK+Mitigations load.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        
    Returns:
        True if verification passed, False otherwise
    """
    verifier = D3FENDVerifier(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        report = verifier.run_full_verification()
        return report["overall_passed"]
    finally:
        verifier.close()