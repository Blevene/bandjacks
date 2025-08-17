#!/usr/bin/env python3
"""Bandjacks CLI - Command-line interface for cyber threat intelligence operations."""

import os
import sys
import json
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import track

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from bandjacks.loaders.hybrid_search import HybridSearcher
from bandjacks.store.candidate_store import CandidateStore
from bandjacks.core.cache import get_cache_manager
from bandjacks.core.connection_pool import get_connection_manager
from bandjacks.core.query_optimizer import QueryOptimizer

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
    ctx.obj['neo4j_password'] = os.getenv('NEO4J_PASSWORD', 'password')
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


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == '__main__':
    main()