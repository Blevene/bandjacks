#!/usr/bin/env python3
"""Generate OpenAPI specification JSON file."""

import json
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bandjacks.services.api.main import app


def generate_openapi_spec():
    """Generate and save OpenAPI specification."""
    
    # Get OpenAPI schema
    openapi_schema = app.openapi()
    
    # Add additional metadata
    openapi_schema["info"]["contact"] = {
        "name": "Bandjacks Team",
        "email": "support@bandjacks.io"
    }
    
    openapi_schema["info"]["license"] = {
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    }
    
    # Add security schemes (for future)
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT authentication (future implementation)"
        },
        "apiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key authentication (future implementation)"
        }
    }
    
    # Add example responses
    openapi_schema["components"]["responses"] = {
        "NotFound": {
            "description": "Resource not found",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {"type": "string"}
                        }
                    },
                    "example": {
                        "detail": "Resource not found"
                    }
                }
            }
        },
        "BadRequest": {
            "description": "Invalid request",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {"type": "string"}
                        }
                    },
                    "example": {
                        "detail": "Invalid parameters provided"
                    }
                }
            }
        },
        "InternalError": {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {"type": "string"}
                        }
                    },
                    "example": {
                        "detail": "An internal error occurred"
                    }
                }
            }
        }
    }
    
    # Save to file
    output_path = "docs/openapi.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump(openapi_schema, f, indent=2)
    
    print(f"✅ OpenAPI specification saved to {output_path}")
    
    # Print summary
    print(f"\nAPI Summary:")
    print(f"  Title: {openapi_schema['info']['title']}")
    print(f"  Version: {openapi_schema['info']['version']}")
    print(f"  Endpoints: {len(openapi_schema['paths'])}")
    
    # Count by method
    methods = {}
    for path, operations in openapi_schema["paths"].items():
        for method in operations:
            if method in ["get", "post", "put", "delete", "patch"]:
                methods[method] = methods.get(method, 0) + 1
    
    print(f"\nEndpoints by method:")
    for method, count in methods.items():
        print(f"  {method.upper()}: {count}")
    
    # List tags
    if "tags" in openapi_schema:
        print(f"\nAPI Tags ({len(openapi_schema['tags'])}):")
        for tag in openapi_schema["tags"]:
            print(f"  - {tag['name']}: {tag.get('description', 'No description')}")
    
    return openapi_schema


if __name__ == "__main__":
    generate_openapi_spec()