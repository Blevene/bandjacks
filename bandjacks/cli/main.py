#!/usr/bin/env python3
"""Bandjacks CLI - Command-line interface for cyber threat intelligence operations."""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import track

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Removed top-level HybridSearcher import to avoid optional dependency at import time
from bandjacks.store.candidate_store import CandidateStore
from bandjacks.core.cache import get_cache_manager
from bandjacks.core.connection_pool import get_connection_manager
from bandjacks.core.query_optimizer import QueryOptimizer

# New imports for analytics CLI
from neo4j import GraphDatabase
from bandjacks.analytics.cooccurrence import (
    CooccurrenceAnalyzer,
)

console = Console()


@click.group()
@click.option('--debug/--no-debug', default=False, help='Enable debug output')
@click.pass_context
def cli(ctx, debug):
    """Bandjacks CLI - Cyber Threat Intelligence Operations."""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['console'] = console
    
    # Load settings from environment
    ctx.obj['neo4j_uri'] = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
    ctx.obj['neo4j_user'] = os.getenv('NEO4J_USER', 'neo4j')
    ctx.obj['neo4j_password'] = os.getenv('NEO4J_PASSWORD', '')  # Must be set via environment variable
    ctx.obj['opensearch_url'] = os.getenv('OPENSEARCH_URL', 'http://localhost:9200')
    ctx.obj['opensearch_index'] = os.getenv('OS_INDEX_NODES', 'bandjacks_attack_nodes-v1')


@cli.group()
@click.pass_context
def query(ctx):
    """Query and search operations."""
    pass


@query.command()
@click.argument('search_query')
@click.option('--top-k', default=10, help='Number of results')
@click.option('--entity-type', help='Filter by entity type')
@click.option('--no-context', is_flag=True, help='Skip graph context')
@click.pass_context
def search(ctx, search_query, top_k, entity_type, no_context):
    """Search for threat intelligence using natural language."""
    console = ctx.obj['console']
    
    with console.status("[bold green]Searching..."):
        try:
            # Lazy import to avoid requiring OpenSearch when not using search
            from bandjacks.loaders.hybrid_search import HybridSearcher
            
            searcher = HybridSearcher(
                ctx.obj['opensearch_url'],
                ctx.obj['opensearch_index'],
                ctx.obj['neo4j_uri'],
                ctx.obj['neo4j_user'],
                ctx.obj['neo4j_password']
            )
            
            filters = {}
            if entity_type:
                filters['entity_type'] = entity_type
            
            results = searcher.search(
                search_query,
                top_k=top_k,
                filters=filters,
                include_graph_context=not no_context
            )
            
            searcher.close()
            
        except Exception as e:
            console.print(f"[red]Search failed: {e}[/red]")
            return
    
    # Display results
    if not results:
        console.print("[yellow]No results found[/yellow]")
        return
    
    table = Table(title=f"Search Results for: {search_query}")
    table.add_column("Rank", style="cyan", width=6)
    table.add_column("Type", style="magenta")
    table.add_column("Name", style="green")
    table.add_column("Score", style="yellow")
    table.add_column("Preview", width=50)
    
    for result in results[:top_k]:
        preview = result.get('preview', '')[:100] + '...' if len(result.get('preview', '')) > 100 else result.get('preview', '')
        table.add_row(
            str(result.get('fusion_rank', result.get('rank', 0))),
            result.get('type', 'unknown'),
            result.get('name', 'Unknown')[:40],
            f"{result.get('fusion_score', result.get('score', 0)):.3f}",
            preview
        )
    
    console.print(table)
    
    # Show graph context if available
    if not no_context and results[0].get('graph_context'):
        console.print("\n[bold]Graph Context for Top Result:[/bold]")
        context = results[0]['graph_context']
        console.print(f"Neighbors: {context.get('neighbor_count', 0)}")
        for rel in context.get('relationships', [])[:5]:
            console.print(f"  - {rel['type']} ({rel['direction']})")


@query.command()
@click.argument('technique_id')
@click.option('--depth', default=2, help='Traversal depth')
@click.pass_context
def graph(ctx, technique_id, depth):
    """Explore graph relationships around a technique."""
    console = ctx.obj['console']
    
    with console.status("[bold green]Traversing graph..."):
        try:
            from neo4j import GraphDatabase
            
            driver = GraphDatabase.driver(
                ctx.obj['neo4j_uri'],
                auth=(ctx.obj['neo4j_user'], ctx.obj['neo4j_password'])
            )
            
            with driver.session() as session:
                query = """
                    MATCH path = (n {stix_id: $stix_id})-[*1..$depth]-(m)
                    WHERE NOT m:Archive
                    WITH n, m, length(path) as distance
                    RETURN 
                        m.stix_id as id,
                        m.name as name,
                        labels(m)[0] as type,
                        distance
                    ORDER BY distance, name
                    LIMIT 50
                """
                
                result = session.run(
                    query,
                    stix_id=technique_id,
                    depth=depth
                )
                
                nodes = list(result)
            
            driver.close()
            
        except Exception as e:
            console.print(f"[red]Graph traversal failed: {e}[/red]")
            return
    
    if not nodes:
        console.print(f"[yellow]No nodes found around {technique_id}[/yellow]")
        return
    
    # Group by distance
    by_distance = {}
    for node in nodes:
        dist = node['distance']
        if dist not in by_distance:
            by_distance[dist] = []
        by_distance[dist].append(node)
    
    console.print(Panel(f"[bold]Graph Exploration: {technique_id}[/bold]"))
    
    for distance in sorted(by_distance.keys()):
        console.print(f"\n[cyan]Distance {distance}:[/cyan]")
        for node in by_distance[distance]:
            console.print(f"  • [{node['type']}] {node['name']} ({node['id']})")


@cli.group()
@click.pass_context
def review(ctx):
    """Review queue management."""
    pass


@review.command()
@click.option('--status', help='Filter by status')
@click.option('--limit', default=20, help='Number of items')
@click.pass_context
def queue(ctx, status, limit):
    """Show review queue."""
    console = ctx.obj['console']
    
    with console.status("[bold green]Loading queue..."):
        try:
            store = CandidateStore(
                ctx.obj['neo4j_uri'],
                ctx.obj['neo4j_user'],
                ctx.obj['neo4j_password']
            )
            
            candidates = store.get_queue(
                status=status,
                limit=limit
            )
            
            stats = store.get_statistics()
            store.close()
            
        except Exception as e:
            console.print(f"[red]Failed to load queue: {e}[/red]")
            return
    
    # Show statistics
    console.print(Panel(f"""[bold]Review Queue Statistics[/bold]
    
Total Candidates: {stats['total_candidates']}
Pending Review: {stats['pending_review']}
Auto-approved: {stats['auto_approved']}
Recent (24h): {stats['recent_24h']}"""))
    
    if not candidates:
        console.print("[yellow]No candidates in queue[/yellow]")
        return
    
    # Show candidates
    table = Table(title="Review Queue")
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Type", style="magenta")
    table.add_column("Name", style="green")
    table.add_column("Confidence", style="yellow")
    table.add_column("Status", style="blue")
    
    for candidate in candidates[:limit]:
        table.add_row(
            candidate['id'][:20],
            candidate.get('type', 'unknown'),
            candidate.get('name', 'Unknown')[:30],
            f"{candidate.get('extraction_confidence', 0):.1f}%",
            candidate.get('status', 'pending')
        )
    
    console.print(table)


@review.command()
@click.argument('candidate_id')
@click.option('--reviewer', default='cli-user', help='Reviewer ID')
@click.option('--merge/--no-merge', default=True, help='Merge to graph')
@click.pass_context
def approve(ctx, candidate_id, reviewer, merge):
    """Approve a candidate."""
    console = ctx.obj['console']
    
    try:
        store = CandidateStore(
            ctx.obj['neo4j_uri'],
            ctx.obj['neo4j_user'],
            ctx.obj['neo4j_password']
        )
        
        result = store.approve_candidate(
            candidate_id,
            reviewer,
            merge
        )
        
        store.close()
        
        if result['merged']:
            console.print(f"[green]✓ Approved and merged: {result['merged_stix_id']}[/green]")
        else:
            console.print(f"[green]✓ Approved: {candidate_id}[/green]")
        
    except Exception as e:
        console.print(f"[red]Approval failed: {e}[/red]")


@review.command()
@click.argument('candidate_id')
@click.option('--reviewer', default='cli-user', help='Reviewer ID')
@click.option('--reason', required=True, help='Rejection reason')
@click.pass_context
def reject(ctx, candidate_id, reviewer, reason):
    """Reject a candidate."""
    console = ctx.obj['console']
    
    try:
        store = CandidateStore(
            ctx.obj['neo4j_uri'],
            ctx.obj['neo4j_user'],
            ctx.obj['neo4j_password']
        )
        
        result = store.reject_candidate(
            candidate_id,
            reviewer,
            reason
        )
        
        store.close()
        
        console.print(f"[red]✗ Rejected: {candidate_id}[/red]")
        console.print(f"  Reason: {reason}")
        
    except Exception as e:
        console.print(f"[red]Rejection failed: {e}[/red]")


@cli.group()
@click.pass_context
def extract(ctx):
    """Document extraction operations."""
    pass


@extract.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--confidence-threshold', default=80.0, help='Auto-approval threshold')
@click.option('--show-evidence', is_flag=True, help='Show evidence')
@click.pass_context
def document(ctx, file_path, confidence_threshold, show_evidence):
    """Extract CTI from a document."""
    console = ctx.obj['console']
    
    console.print(f"[bold]Extracting from: {file_path}[/bold]")
    
    with console.status("[bold green]Processing document..."):
        try:
            from bandjacks.llm.processor import LLMProcessor
            from bandjacks.llm.stix_builder import STIXBuilder
            
            # Initialize processor
            processor = LLMProcessor(model_name="gemini/gemini-2.0-flash-exp")
            
            # Read file
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract entities
            results = processor.extract_entities(content, file_path)
            
            if not results:
                console.print("[yellow]No entities extracted[/yellow]")
                return
            
        except Exception as e:
            console.print(f"[red]Extraction failed: {e}[/red]")
            return
    
    if not results:
        console.print("[yellow]No entities extracted[/yellow]")
        return
    
    console.print(f"\n[green]Extracted {len(results.get('entities', []))} entities[/green]")
    
    # Show entities
    for entity in results.get('entities', []):
        console.print(f"\n[bold]{entity['type']}: {entity['name']}[/bold]")
        console.print(f"  Confidence: {entity.get('confidence', 0)}%")
        
        if show_evidence and entity.get('evidence'):
            console.print("  Evidence:")
            for ev in entity['evidence'][:2]:
                console.print(f"    • Line {ev['line']}: {ev['text'][:100]}...")
    
    # Show relationships
    if results.get('relationships'):
        console.print(f"\n[cyan]Found {len(results['relationships'])} relationships[/cyan]")


@cli.group()
@click.pass_context
def admin(ctx):
    """Administrative operations."""
    pass


@admin.command()
@click.pass_context
def optimize(ctx):
    """Optimize database performance."""
    console = ctx.obj['console']
    
    with console.status("[bold green]Running optimization..."):
        try:
            optimizer = QueryOptimizer(
                ctx.obj['neo4j_uri'],
                ctx.obj['neo4j_user'],
                ctx.obj['neo4j_password']
            )
            
            # Create indexes
            console.print("[cyan]Creating indexes...[/cyan]")
            index_results = optimizer.create_indexes()
            
            # Get recommendations
            console.print("[cyan]Analyzing queries...[/cyan]")
            recommendations = optimizer.optimize_common_queries()
            
            optimizer.close()
            
        except Exception as e:
            console.print(f"[red]Optimization failed: {e}[/red]")
            return
    
    # Show results
    console.print("\n[bold]Index Creation Results:[/bold]")
    for name, success in index_results.items():
        status = "[green]✓[/green]" if success else "[red]✗[/red]"
        console.print(f"  {status} {name}")
    
    if recommendations:
        console.print("\n[bold]Optimization Recommendations:[/bold]")
        for rec in recommendations:
            console.print(f"  • [{rec['impact']}] {rec['recommendation']}")


@admin.command()
@click.pass_context
def cache_stats(ctx):
    """Show cache statistics."""
    console = ctx.obj['console']
    
    try:
        cache = get_cache_manager()
        stats = cache.get_stats()
        
        if not stats.get('enabled'):
            console.print("[yellow]Cache is disabled[/yellow]")
            return
        
        if not stats.get('connected'):
            console.print("[red]Cache not connected[/red]")
            return
        
        table = Table(title="Cache Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Hit Rate", f"{stats.get('hit_rate', 0):.2%}")
        table.add_row("Total Hits", str(stats.get('hits', 0)))
        table.add_row("Total Misses", str(stats.get('misses', 0)))
        table.add_row("Memory Used", stats.get('memory_used', '0'))
        table.add_row("Commands Processed", str(stats.get('commands_processed', 0)))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Failed to get cache stats: {e}[/red]")


@admin.command()
@click.option('--pattern', help='Pattern to invalidate')
@click.pass_context
def cache_clear(ctx, pattern):
    """Clear cache entries."""
    console = ctx.obj['console']
    
    try:
        cache = get_cache_manager()
        
        if pattern:
            count = cache.invalidate("search", pattern)
            console.print(f"[green]Cleared {count} entries matching '{pattern}'[/green]")
        else:
            count = cache.invalidate("search")
            count += cache.invalidate("graph")
            console.print(f"[green]Cleared {count} total cache entries[/green]")
        
    except Exception as e:
        console.print(f"[red]Failed to clear cache: {e}[/red]")


@admin.command()
@click.pass_context
def health(ctx):
    """Check system health."""
    console = ctx.obj['console']
    
    with console.status("[bold green]Checking health..."):
        try:
            conn_manager = get_connection_manager()
            
            # Initialize connections if needed
            conn_manager.init_neo4j(
                ctx.obj['neo4j_uri'],
                ctx.obj['neo4j_user'],
                ctx.obj['neo4j_password']
            )
            conn_manager.init_opensearch([ctx.obj['opensearch_url']])
            
            health = conn_manager.health_check()
            
        except Exception as e:
            console.print(f"[red]Health check failed: {e}[/red]")
            return
    
    console.print("[bold]System Health Status:[/bold]\n")
    
    for service, status in health.items():
        icon = "[green]✓[/green]" if status else "[red]✗[/red]"
        console.print(f"  {icon} {service}: {'Online' if status else 'Offline'}")
    
    # Check cache
    try:
        cache = get_cache_manager()
        cache_stats = cache.get_stats()
        if cache_stats.get('connected'):
            console.print(f"  [green]✓[/green] Redis: Online")
        else:
            console.print(f"  [yellow]⚠[/yellow] Redis: Not connected")
    except:
        console.print(f"  [yellow]⚠[/yellow] Redis: Not available")


@cli.group()
@click.pass_context
def analytics(ctx):
    """Analytics and co-occurrence operations."""
    pass


@cli.group()
@click.pass_context
def workflow(ctx):
    """End-to-end workflows for extraction and analytics."""
    pass


@analytics.command("top-cooccurrence")
@click.option('--limit', default=25, help='Max pairs to return', show_default=True)
@click.option('--min-episode-size', default=2, help='Min actions per episode to count', show_default=True)
@click.option('--tactic', default=None, help='Filter by tactic shortname (e.g., discovery)')
@click.pass_context
def analytics_top_cooccurrence(ctx, limit, min_episode_size, tactic):
    """Show top co-occurring technique pairs across all episodes."""
    neo4j_uri = ctx.obj['neo4j_uri']
    neo4j_user = ctx.obj['neo4j_user']
    neo4j_password = ctx.obj['neo4j_password']

    with console.status("[bold green]Computing co-occurrence pairs..."):
        try:
            driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            with driver.session() as session:
                query = """
                    MATCH (e:AttackEpisode)
                    WITH e
                    MATCH (e)-[:CONTAINS]->(a1:AttackAction)
                    MATCH (e)-[:CONTAINS]->(a2:AttackAction)
                    WHERE a1.attack_pattern_ref < a2.attack_pattern_ref
                    WITH e, a1, a2
                    OPTIONAL MATCH (t1:AttackPattern {stix_id: a1.attack_pattern_ref})-[:HAS_TACTIC]->(ta1:Tactic)
                    OPTIONAL MATCH (t2:AttackPattern {stix_id: a2.attack_pattern_ref})-[:HAS_TACTIC]->(ta2:Tactic)
                    WITH e, a1, a2,
                         coalesce(ta1.shortname, "") as tact1,
                         coalesce(ta2.shortname, "") as tact2
                    WHERE $tactic IS NULL OR tact1 = $tactic OR tact2 = $tactic
                    WITH e, collect(DISTINCT a1.attack_pattern_ref) as tset1,
                           collect(DISTINCT a2.attack_pattern_ref) as tset2
                    WITH apoc.coll.toSet(tset1 + tset2) as techniques, e
                    WHERE size(techniques) >= $min_episode_size
                    UNWIND techniques as tA
                    UNWIND techniques as tB
                    WITH tA, tB
                    WHERE tA < tB
                    WITH tA as technique_a, tB as technique_b, count(*) as cnt
                    ORDER BY cnt DESC
                    LIMIT $limit
                    WITH technique_a, technique_b, cnt
                    OPTIONAL MATCH (pa:AttackPattern {stix_id: technique_a})
                    OPTIONAL MATCH (pb:AttackPattern {stix_id: technique_b})
                    RETURN technique_a, coalesce(pa.name, technique_a) as name_a,
                           technique_b, coalesce(pb.name, technique_b) as name_b, cnt
                """
                rows = session.run(
                    query,
                    limit=limit,
                    min_episode_size=min_episode_size,
                    tactic=tactic,
                )
                data = list(rows)
        except Exception as e:
            console.print(f"[red]Failed: {e}[/red]")
            return
        finally:
            try:
                driver.close()
            except Exception:
                pass

    if not data:
        console.print("[yellow]No pairs found[/yellow]")
        return

    table = Table(title="Top Co-occurring Technique Pairs")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Technique A", style="green")
    table.add_column("Technique B", style="green")
    table.add_column("Count", style="yellow", justify="right")

    for idx, rec in enumerate(data, 1):
        table.add_row(
            str(idx),
            f"{rec['name_a']} ({rec['technique_a']})",
            f"{rec['name_b']} ({rec['technique_b']})",
            str(rec['cnt']),
        )
    console.print(table)


@analytics.command("conditional")
@click.argument('technique_id')
@click.option('--limit', default=25, help='Max related techniques to return', show_default=True)
@click.pass_context
def analytics_conditional(ctx, technique_id, limit):
    """Compute conditional co-occurrence P(B|A) for a given technique A."""
    neo4j_uri = ctx.obj['neo4j_uri']
    neo4j_user = ctx.obj['neo4j_user']
    neo4j_password = ctx.obj['neo4j_password']

    with console.status("[bold green]Computing conditional co-occurrence..."):
        try:
            driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            with driver.session() as session:
                query = """
                    MATCH (e:AttackEpisode)-[:CONTAINS]->(aA:AttackAction {attack_pattern_ref: $tech})
                    WITH collect(DISTINCT e) as episodesA
                    WITH episodesA, size(episodesA) as totalA
                    UNWIND episodesA as e
                    MATCH (e)-[:CONTAINS]->(aB:AttackAction)
                    WHERE aB.attack_pattern_ref <> $tech
                    WITH aB.attack_pattern_ref as b, totalA, count(DISTINCT e) as co_count
                    OPTIONAL MATCH (pb:AttackPattern {stix_id: b})
                    RETURN b as technique_id,
                           coalesce(pb.name, b) as name,
                           co_count as co_occurrence_count,
                           totalA as episodes_with_given,
                           (1.0 * co_count) / CASE WHEN totalA = 0 THEN 1 ELSE totalA END as p
                    ORDER BY p DESC, co_occurrence_count DESC
                    LIMIT $limit
                """
                rows = session.run(query, tech=technique_id, limit=limit)
                data = list(rows)
        except Exception as e:
            console.print(f"[red]Failed: {e}[/red]")
            return
        finally:
            try:
                driver.close()
            except Exception:
                pass

    if not data:
        console.print("[yellow]No conditional results found[/yellow]")
        return

    table = Table(title=f"Conditional Co-occurrence given {technique_id}")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Co-technique", style="green")
    table.add_column("Episodes with A", justify="right")
    table.add_column("Co-occurrence", justify="right")
    table.add_column("P(B|A)", style="yellow", justify="right")

    for idx, rec in enumerate(data, 1):
        table.add_row(
            str(idx),
            f"{rec['name']} ({rec['technique_id']})",
            str(rec['episodes_with_given']),
            str(rec['co_occurrence_count']),
            f"{float(rec['p']):.3f}",
        )
    console.print(table)


@analytics.command("actor")
@click.argument('intrusion_set_id')
@click.option('--min-support', default=1, show_default=True, help='Minimum episode support')
@click.option('--metric', type=click.Choice(['npmi', 'lift', 'confidence']), default='npmi', show_default=True)
@click.pass_context
def analytics_actor(ctx, intrusion_set_id, min_support, metric):
    """Analyze co-occurrence for a specific intrusion set (top pairs and bundles)."""
    analyzer = CooccurrenceAnalyzer(
        ctx.obj['neo4j_uri'], ctx.obj['neo4j_user'], ctx.obj['neo4j_password']
    )
    try:
        metrics = analyzer.calculate_actor_cooccurrence(intrusion_set_id, min_support)

        if metric == 'lift':
            metrics.sort(key=lambda m: m.lift, reverse=True)
        elif metric == 'confidence':
            metrics.sort(key=lambda m: max(m.confidence_a_to_b, m.confidence_b_to_a), reverse=True)
        else:
            metrics.sort(key=lambda m: m.npmi, reverse=True)

        table = Table(title=f"Actor Co-occurrence: {intrusion_set_id}")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Technique A", style="green")
        table.add_column("Technique B", style="green")
        table.add_column("Count", justify="right")
        table.add_column("Conf A→B", justify="right")
        table.add_column("Conf B→A", justify="right")
        table.add_column("Lift", justify="right")
        table.add_column("NPMI", style="yellow", justify="right")

        # Resolve names in one go for the top rows
        top = metrics[:20]
        if top:
            driver = GraphDatabase.driver(ctx.obj['neo4j_uri'], auth=(ctx.obj['neo4j_user'], ctx.obj['neo4j_password']))
            try:
                ids = sorted({tid for m in top for tid in (m.technique_a, m.technique_b)})
                with driver.session() as session:
                    name_rows = session.run(
                        """
                        MATCH (t:AttackPattern)
                        WHERE t.stix_id IN $ids
                        RETURN t.stix_id as id, t.name as name
                        """,
                        ids=ids,
                    )
                    name_map = {r['id']: r['name'] for r in name_rows}
            finally:
                driver.close()
        else:
            name_map = {}

        for idx, m in enumerate(top, 1):
            a = f"{name_map.get(m.technique_a, m.technique_a)} ({m.technique_a})"
            b = f"{name_map.get(m.technique_b, m.technique_b)} ({m.technique_b})"
            table.add_row(
                str(idx), a, b,
                str(m.count),
                f"{m.confidence_a_to_b:.3f}",
                f"{m.confidence_b_to_a:.3f}",
                f"{m.lift:.2f}",
                f"{m.npmi:.3f}",
            )
        console.print(table)

        # Bundles
        bundles = analyzer.extract_technique_bundles(
            intrusion_set_id, min_support=min_support, min_size=3, max_size=5
        )
        if bundles:
            btable = Table(title="Signature Bundles (top)")
            btable.add_column("Techniques", style="green")
            btable.add_column("Support", justify="right")
            btable.add_column("Confidence", justify="right")
            btable.add_column("Lift", justify="right")
            btable.add_column("Tactics")
            for b in bundles[:10]:
                btable.add_row(
                    ", ".join(b.techniques),
                    str(b.support),
                    f"{b.confidence:.3f}",
                    f"{b.lift:.2f}",
                    ", ".join(b.tactics),
                )
            console.print(btable)
        else:
            console.print("[yellow]No bundles found[/yellow]")

    except Exception as e:
        console.print(f"[red]Actor analysis failed: {e}[/red]")
    finally:
        analyzer.close()


@analytics.command("bundles")
@click.option('--min-support', default=3, show_default=True)
@click.option('--min-size', default=3, show_default=True)
@click.option('--max-size', default=5, show_default=True)
@click.option('--actor', default=None, help='Optional Intrusion Set STIX ID')
@click.option('--format', type=click.Choice(['table', 'csv', 'json']), default='table', help='Output format')
@click.option('--output', type=click.Path(), help='Output file path (required for csv/json)')
@click.pass_context
def analytics_bundles(ctx, min_support, min_size, max_size, actor, format, output):
    """Extract frequently co-occurring technique bundles."""

    # Validate output file for export formats
    if format in ['csv', 'json'] and not output:
        console.print("[red]Error: --output is required for csv/json formats[/red]")
        return

    analyzer = CooccurrenceAnalyzer(
        ctx.obj['neo4j_uri'], ctx.obj['neo4j_user'], ctx.obj['neo4j_password']
    )
    try:
        bundles = analyzer.extract_technique_bundles(
            actor, min_support=min_support, min_size=min_size, max_size=max_size
        )
        if not bundles:
            console.print("[yellow]No bundles found[/yellow]")
            return

        # Sort bundles by lift
        bundles_sorted = sorted(bundles, key=lambda x: x.lift, reverse=True)

        # Export to file if requested
        if format == 'csv':
            from bandjacks.cli.formatters import AnalyticsFormatter
            from pathlib import Path
            AnalyticsFormatter.export_bundles_csv(bundles_sorted, Path(output))
            console.print(f"[green]✓ Exported {len(bundles)} bundles to {output}[/green]")
        elif format == 'json':
            from bandjacks.cli.formatters import AnalyticsFormatter
            from pathlib import Path
            metadata = {
                "analysis_type": "technique_bundles",
                "min_support": min_support,
                "min_size": min_size,
                "max_size": max_size,
                "intrusion_set_filter": actor
            }
            AnalyticsFormatter.export_bundles_json(bundles_sorted, Path(output), metadata)
            console.print(f"[green]✓ Exported {len(bundles)} bundles to {output}[/green]")
        else:
            # Display table format
            table = Table(title="Technique Bundles")
            table.add_column("#", style="cyan", width=4)
            table.add_column("Techniques", style="green")
            table.add_column("Support", justify="right")
            table.add_column("Confidence", justify="right")
            table.add_column("Lift", justify="right")
            table.add_column("Tactics")
            for idx, b in enumerate(bundles_sorted[:25], 1):
                table.add_row(
                    str(idx),
                    ", ".join(b.techniques),
                    str(b.support),
                    f"{b.confidence:.3f}",
                    f"{b.lift:.2f}",
                    ", ".join(b.tactics),
                )
            console.print(table)
    except Exception as e:
        console.print(f"[red]Bundle extraction failed: {e}[/red]")
    finally:
        analyzer.close()


@analytics.command("global")
@click.option('--min-support', default=2, show_default=True)
@click.option('--min-episodes-per-pair', default=2, show_default=True)
@click.option('--limit', default=50, show_default=True)
@click.option('--format', type=click.Choice(['table', 'csv', 'json']), default='table', help='Output format')
@click.option('--output', type=click.Path(), help='Output file path (required for csv/json)')
@click.pass_context
def analytics_global(ctx, min_support, min_episodes_per_pair, limit, format, output):
    """Compute global co-occurrence metrics (PMI/NPMI, Lift) across all episodes."""

    # Validate output file for export formats
    if format in ['csv', 'json'] and not output:
        console.print("[red]Error: --output is required for csv/json formats[/red]")
        return

    analyzer = CooccurrenceAnalyzer(
        ctx.obj['neo4j_uri'], ctx.obj['neo4j_user'], ctx.obj['neo4j_password']
    )
    try:
        metrics = analyzer.calculate_global_cooccurrence(
            min_support=min_support,
            min_episodes_per_pair=min_episodes_per_pair,
        )
        metrics = metrics[:limit]
        if not metrics:
            console.print("[yellow]No co-occurrence pairs found[/yellow]")
            return

        # Resolve names in batch
        driver = GraphDatabase.driver(ctx.obj['neo4j_uri'], auth=(ctx.obj['neo4j_user'], ctx.obj['neo4j_password']))
        try:
            ids = sorted({tid for m in metrics for tid in (m.technique_a, m.technique_b)})
            with driver.session() as session:
                name_rows = session.run(
                    """
                    MATCH (t:AttackPattern)
                    WHERE t.stix_id IN $ids
                    RETURN t.stix_id as id, t.name as name
                    """,
                    ids=ids,
                )
                name_map = {r['id']: r['name'] for r in name_rows}
        finally:
            driver.close()

        # Export to file if requested
        if format == 'csv':
            from bandjacks.cli.formatters import AnalyticsFormatter
            from pathlib import Path
            AnalyticsFormatter.export_cooccurrence_csv(metrics, Path(output), name_map)
            console.print(f"[green]✓ Exported {len(metrics)} pairs to {output}[/green]")
        elif format == 'json':
            from bandjacks.cli.formatters import AnalyticsFormatter
            from pathlib import Path
            metadata = {
                "analysis_type": "global_cooccurrence",
                "min_support": min_support,
                "min_episodes_per_pair": min_episodes_per_pair
            }
            AnalyticsFormatter.export_cooccurrence_json(metrics, Path(output), name_map, metadata)
            console.print(f"[green]✓ Exported {len(metrics)} pairs to {output}[/green]")
        else:
            # Display table format
            table = Table(title="Global Co-occurrence Metrics")
            table.add_column("#", style="cyan", width=4)
            table.add_column("Technique A", style="green")
            table.add_column("Technique B", style="green")
            table.add_column("Count", justify="right")
            table.add_column("Lift", justify="right")
            table.add_column("PMI", justify="right")
            table.add_column("NPMI", style="yellow", justify="right")
            table.add_column("Jaccard", justify="right")

            for idx, m in enumerate(metrics, 1):
                a = f"{name_map.get(m.technique_a, m.technique_a)} ({m.technique_a})"
                b = f"{name_map.get(m.technique_b, m.technique_b)} ({m.technique_b})"
                table.add_row(
                    str(idx), a, b,
                    str(m.count),
                    f"{m.lift:.2f}",
                    f"{m.pmi:.3f}",
                    f"{m.npmi:.3f}",
                    f"{m.jaccard:.3f}",
                )
            console.print(table)
    except Exception as e:
        console.print(f"[red]Global analysis failed: {e}[/red]")
    finally:
        analyzer.close()


@workflow.command("process-reports")
@click.argument('report_dir', type=click.Path(exists=True))
@click.option('--workers', default=3, help='Number of parallel workers')
@click.option('--analyze', is_flag=True, help='Run analytics after extraction')
@click.option('--export-dir', type=click.Path(), help='Export analytics to directory')
@click.option('--api', is_flag=True, help='Use API for extraction')
@click.pass_context
def workflow_process_reports(ctx, report_dir, workers, analyze, export_dir, api):
    """
    Process a directory of reports and optionally run analytics.

    Example:
        bandjacks workflow process-reports ./reports/ --analyze --export-dir ./results/
    """
    console.print(Panel("[bold]Report Processing Workflow[/bold]", style="blue"))

    report_path = Path(report_dir)

    # Step 1: Extract reports
    console.print("\n[bold cyan]Step 1: Extracting techniques from reports[/bold cyan]")

    extract_cmd = [
        sys.executable, "-m", "bandjacks.cli.batch_extract",
        str(report_path),
        "--workers", str(workers),
        "--store-in-neo4j",
        "--neo4j-uri", ctx.obj['neo4j_uri'],
        "--neo4j-user", ctx.obj['neo4j_user'],
        "--neo4j-password", ctx.obj['neo4j_password']
    ]

    if api:
        extract_cmd.append("--api")

    console.print(f"[dim]Running extraction...[/dim]")
    result = subprocess.run(extract_cmd)

    if result.returncode != 0:
        console.print("[red]✗ Extraction failed[/red]")
        return

    console.print("[green]✓ Extraction complete[/green]")

    # Step 2: Run analytics if requested
    if analyze:
        console.print("\n[bold cyan]Step 2: Running co-occurrence analytics[/bold cyan]")

        if export_dir:
            export_path = Path(export_dir)
            export_path.mkdir(parents=True, exist_ok=True)

            # Run global co-occurrence analysis
            console.print("[yellow]→ Computing global co-occurrence metrics...[/yellow]")
            from bandjacks.analytics.cooccurrence import CooccurrenceAnalyzer
            from bandjacks.cli.formatters import AnalyticsFormatter
            from neo4j import GraphDatabase

            analyzer = CooccurrenceAnalyzer(
                ctx.obj['neo4j_uri'], ctx.obj['neo4j_user'], ctx.obj['neo4j_password']
            )

            try:
                metrics = analyzer.calculate_global_cooccurrence(min_support=2, min_episodes_per_pair=2)
                metrics = metrics[:100]

                # Get technique names
                driver = GraphDatabase.driver(ctx.obj['neo4j_uri'], auth=(ctx.obj['neo4j_user'], ctx.obj['neo4j_password']))
                try:
                    ids = sorted({tid for m in metrics for tid in (m.technique_a, m.technique_b)})
                    with driver.session() as session:
                        name_rows = session.run(
                            "MATCH (t:AttackPattern) WHERE t.stix_id IN $ids RETURN t.stix_id as id, t.name as name",
                            ids=ids
                        )
                        name_map = {r['id']: r['name'] for r in name_rows}
                finally:
                    driver.close()

                # Export
                AnalyticsFormatter.export_cooccurrence_csv(metrics, export_path / "global_cooccurrence.csv", name_map)
                console.print(f"[green]✓ Exported {len(metrics)} pairs to {export_path / 'global_cooccurrence.csv'}[/green]")

                # Bundles
                console.print("[yellow]→ Extracting technique bundles...[/yellow]")
                bundles = analyzer.extract_technique_bundles(min_support=3, min_size=3, max_size=5)
                AnalyticsFormatter.export_bundles_json(bundles, export_path / "technique_bundles.json")
                console.print(f"[green]✓ Exported {len(bundles)} bundles to {export_path / 'technique_bundles.json'}[/green]")
            finally:
                analyzer.close()

            console.print(f"\n[green]✓ Analytics exported to {export_path}[/green]")

    console.print("\n[bold green]✓ Workflow complete![/bold green]")


@workflow.command("bulk-export")
@click.option('--export-dir', type=click.Path(), required=True, help='Export directory')
@click.pass_context
def workflow_bulk_export(ctx, export_dir):
    """
    Export all analytics data (co-occurrence, bundles).

    Example:
        bandjacks workflow bulk-export --export-dir ./analytics_export/
    """
    from pathlib import Path
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from bandjacks.analytics.cooccurrence import CooccurrenceAnalyzer
    from bandjacks.cli.formatters import AnalyticsFormatter
    from neo4j import GraphDatabase

    console.print(Panel("[bold]Bulk Analytics Export[/bold]", style="blue"))

    export_path = Path(export_dir)
    export_path.mkdir(parents=True, exist_ok=True)

    analyzer = CooccurrenceAnalyzer(
        ctx.obj['neo4j_uri'], ctx.obj['neo4j_user'], ctx.obj['neo4j_password']
    )

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            # Global co-occurrence
            task1 = progress.add_task("Exporting global co-occurrence...", total=None)
            metrics = analyzer.calculate_global_cooccurrence(min_support=2, min_episodes_per_pair=2)
            metrics = metrics[:500]

            # Get technique names
            driver = GraphDatabase.driver(ctx.obj['neo4j_uri'], auth=(ctx.obj['neo4j_user'], ctx.obj['neo4j_password']))
            try:
                ids = sorted({tid for m in metrics for tid in (m.technique_a, m.technique_b)})
                with driver.session() as session:
                    name_rows = session.run(
                        "MATCH (t:AttackPattern) WHERE t.stix_id IN $ids RETURN t.stix_id as id, t.name as name",
                        ids=ids
                    )
                    name_map = {r['id']: r['name'] for r in name_rows}
            finally:
                driver.close()

            AnalyticsFormatter.export_cooccurrence_csv(metrics, export_path / "global_cooccurrence.csv", name_map)
            AnalyticsFormatter.export_cooccurrence_json(metrics, export_path / "global_cooccurrence.json", name_map)
            progress.update(task1, completed=True)

            # Bundles
            task2 = progress.add_task("Exporting technique bundles...", total=None)
            bundles = analyzer.extract_technique_bundles(min_support=3, min_size=3, max_size=5)
            AnalyticsFormatter.export_bundles_csv(bundles, export_path / "technique_bundles.csv")
            AnalyticsFormatter.export_bundles_json(bundles, export_path / "technique_bundles.json")
            progress.update(task2, completed=True)

    finally:
        analyzer.close()

    console.print(f"\n[bold green]✓ Analytics data exported to {export_path}[/bold green]")
    console.print("\nExported files:")
    for file in export_path.glob("*"):
        console.print(f"  • {file.name}")


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == '__main__':
    main()