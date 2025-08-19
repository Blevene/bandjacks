#!/usr/bin/env python3
"""Check OpenAPI compliance of all API endpoints."""

import re
import ast
from pathlib import Path
from collections import defaultdict

def analyze_route_file(file_path):
    """Analyze a route file for OpenAPI compliance."""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find all router decorators
    router_pattern = r'@router\.(get|post|put|delete|patch)\s*\('
    decorators = re.findall(router_pattern, content, re.MULTILINE)
    
    # Count endpoints with response_model
    response_model_count = len(re.findall(r'response_model\s*=', content))
    
    # Count endpoints with summary
    summary_count = len(re.findall(r'summary\s*=', content))
    
    # Count endpoints with description
    description_count = len(re.findall(r'description\s*=', content))
    
    # Count endpoints with operation_id
    operation_id_count = len(re.findall(r'operation_id\s*=', content))
    
    # Count endpoints with explicit status codes
    status_code_count = len(re.findall(r'status_code\s*=', content))
    
    return {
        'file': file_path.name,
        'total_endpoints': len(decorators),
        'response_model': response_model_count,
        'summary': summary_count,
        'description': description_count,
        'operation_id': operation_id_count,
        'status_code': status_code_count
    }

def main():
    routes_dir = Path('bandjacks/services/api/routes')
    
    if not routes_dir.exists():
        print("Routes directory not found")
        return
    
    print("🔍 OpenAPI Compliance Analysis")
    print("=" * 80)
    
    files_data = []
    totals = defaultdict(int)
    
    for route_file in routes_dir.glob('*.py'):
        if route_file.name.startswith('__') or route_file.name.startswith('._'):
            continue
            
        data = analyze_route_file(route_file)
        files_data.append(data)
        
        for key, value in data.items():
            if key != 'file':
                totals[key] += value
    
    # Print per-file results
    print("\nPer-file Analysis:")
    print("-" * 80)
    print(f"{'File':<25} {'Endpoints':<10} {'ResponseModel':<13} {'Summary':<8} {'Description':<12} {'OperationID':<12} {'StatusCode':<11}")
    print("-" * 80)
    
    for data in sorted(files_data, key=lambda x: x['total_endpoints'], reverse=True):
        name = data['file'][:24]
        print(f"{name:<25} {data['total_endpoints']:<10} "
              f"{data['response_model']:<13} {data['summary']:<8} "
              f"{data['description']:<12} {data['operation_id']:<12} "
              f"{data['status_code']:<11}")
    
    print("\n" + "=" * 80)
    print("📊 Summary")
    print("=" * 80)
    
    total_endpoints = totals['total_endpoints']
    
    print(f"Total API endpoints: {total_endpoints}")
    print(f"")
    
    compliance_metrics = [
        ("Response models", totals['response_model'], "✅ Type safety"),
        ("Summaries", totals['summary'], "📝 Short descriptions"),
        ("Descriptions", totals['description'], "📖 Detailed docs"),
        ("Operation IDs", totals['operation_id'], "🔧 SDK generation"),
        ("Status codes", totals['status_code'], "📋 HTTP status")
    ]
    
    for metric, count, description in compliance_metrics:
        percentage = (count / total_endpoints * 100) if total_endpoints > 0 else 0
        status = "🟢" if percentage >= 90 else "🟡" if percentage >= 70 else "🔴"
        print(f"{status} {metric:<15}: {count:>3}/{total_endpoints} ({percentage:5.1f}%) - {description}")
    
    print("\n" + "=" * 80)
    print("🎯 OpenAPI Compliance Score")
    print("=" * 80)
    
    # Calculate overall compliance score
    weights = {
        'response_model': 0.3,  # Most important - type safety
        'summary': 0.2,        # Important for docs
        'description': 0.2,    # Important for detailed docs
        'operation_id': 0.15,  # Important for SDK generation
        'status_code': 0.15    # Important for proper HTTP
    }
    
    overall_score = 0
    for metric, weight in weights.items():
        if total_endpoints > 0:
            score = (totals[metric] / total_endpoints) * weight
            overall_score += score
    
    overall_percentage = overall_score * 100
    
    if overall_percentage >= 90:
        grade = "🌟 Excellent"
    elif overall_percentage >= 80:
        grade = "✅ Good"
    elif overall_percentage >= 70:
        grade = "🟡 Fair"
    elif overall_percentage >= 60:
        grade = "🟠 Poor"
    else:
        grade = "🔴 Needs Work"
    
    print(f"Overall Compliance: {overall_percentage:.1f}% ({grade})")
    
    # Recommendations
    print("\n" + "=" * 80)
    print("💡 Recommendations")
    print("=" * 80)
    
    missing_response_models = total_endpoints - totals['response_model']
    missing_summaries = total_endpoints - totals['summary']
    missing_descriptions = total_endpoints - totals['description']
    missing_operation_ids = total_endpoints - totals['operation_id']
    
    if missing_response_models > 0:
        print(f"• Add response_model to {missing_response_models} endpoints for type safety")
    
    if missing_summaries > 0:
        print(f"• Add summary to {missing_summaries} endpoints for better API docs")
        
    if missing_descriptions > 0:
        print(f"• Add description to {missing_descriptions} endpoints for detailed docs")
        
    if missing_operation_ids > 0:
        print(f"• Add operation_id to {missing_operation_ids} endpoints for SDK generation")
    
    if overall_percentage < 80:
        print("• Focus on response models and summaries first - they have the biggest impact")
        print("• Consider using a consistent pattern across all endpoints")
    
    print("\n✨ OpenAPI analysis complete!")

if __name__ == "__main__":
    main()