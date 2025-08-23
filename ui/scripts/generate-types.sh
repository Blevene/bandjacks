#!/bin/bash

# Generate TypeScript types from OpenAPI spec
echo "Fetching OpenAPI spec from backend..."

# Try to fetch from running backend
if curl -s http://localhost:8001/openapi.json -o openapi.json; then
  echo "✓ OpenAPI spec fetched successfully"
else
  echo "✗ Backend not running. Please start the backend and run this script again."
  exit 1
fi

# Generate TypeScript types
echo "Generating TypeScript types..."
npx openapi-typescript openapi.json -o lib/api-types.ts

echo "✓ Types generated successfully at lib/api-types.ts"

# Optional: Generate axios client
# npx openapi-generator-cli generate -i openapi.json -g typescript-axios -o lib/generated