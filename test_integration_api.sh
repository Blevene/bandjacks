#!/bin/bash

echo "=========================================="
echo "INTEGRATION TEST: Entity Evidence Consolidation"
echo "=========================================="

# Read the test document
CONTENT=$(cat test_integration_entities.txt)

# Submit the document (should use async due to size)
echo -e "\n1. Submitting document to API..."
RESPONSE=$(curl -s -X POST "http://localhost:8000/v1/reports/ingest_async" \
  -H "Content-Type: application/json" \
  -d "{
    \"text\": $(echo "$CONTENT" | jq -Rs .),
    \"source\": \"integration_test\",
    \"title\": \"APT29 SolarWinds Test\",
    \"config\": {
      \"use_chunked\": true,
      \"chunk_size\": 2000,
      \"max_chunks\": 5
    }
  }")

# Extract job ID
JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id')
echo "   Job ID: $JOB_ID"

# Poll for completion
echo -e "\n2. Polling job status..."
for i in {1..60}; do
  sleep 5
  STATUS_RESPONSE=$(curl -s "http://localhost:8000/v1/reports/jobs/$JOB_ID/status")
  JOB_STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
  PROGRESS=$(echo "$STATUS_RESPONSE" | jq -r '.progress // 0')
  
  echo "   Attempt $i: Status=$JOB_STATUS, Progress=$PROGRESS%"
  
  if [ "$JOB_STATUS" = "completed" ]; then
    echo -e "\n3. Job completed successfully!"
    
    # Extract entities
    echo -e "\n4. Extracted Entities:"
    ENTITIES=$(echo "$STATUS_RESPONSE" | jq -r '.result.extraction.entities.entities // []')
    
    if [ "$ENTITIES" != "[]" ]; then
      # Count entities
      ENTITY_COUNT=$(echo "$ENTITIES" | jq 'length')
      echo "   Total entities: $ENTITY_COUNT"
      
      # Show key entities with evidence
      echo -e "\n   Key entities with evidence:"
      echo "$ENTITIES" | jq -r '.[] | select(.name | test("APT29|Cozy|SUNBURST|SolarWinds"; "i")) | 
        "   - \(.name) (\(.type)): confidence=\(.confidence)%, mentions=\(.mentions | length)"'
      
      # Check for APT29/Cozy Bear consolidation
      APT29_COUNT=$(echo "$ENTITIES" | jq '[.[] | select(.name | test("APT29"; "i"))] | length')
      COZY_COUNT=$(echo "$ENTITIES" | jq '[.[] | select(.name | test("Cozy Bear"; "i"))] | length')
      
      echo -e "\n5. Consolidation Check:"
      echo "   APT29 entities: $APT29_COUNT"
      echo "   Cozy Bear entities: $COZY_COUNT"
      
      if [ "$APT29_COUNT" -eq 1 ] && [ "$COZY_COUNT" -eq 0 ]; then
        echo "   ✅ APT29/Cozy Bear properly consolidated!"
        
        # Check if aliases are tracked
        APT29_ENTITY=$(echo "$ENTITIES" | jq '.[] | select(.name | test("APT29"; "i"))')
        ALIASES=$(echo "$APT29_ENTITY" | jq -r '.aliases // []')
        if [ "$ALIASES" != "[]" ]; then
          echo "   ✅ Aliases tracked: $(echo "$ALIASES" | jq -r '. | join(", ")')"
        fi
      elif [ "$COZY_COUNT" -eq 1 ] && [ "$APT29_COUNT" -eq 0 ]; then
        echo "   ✅ Cozy Bear/APT29 properly consolidated (Cozy Bear as primary)!"
      else
        echo "   ⚠️ APT29 and Cozy Bear not properly consolidated"
      fi
      
      # Check SUNBURST mentions
      SUNBURST=$(echo "$ENTITIES" | jq '.[] | select(.name | test("SUNBURST"; "i"))')
      if [ -n "$SUNBURST" ] && [ "$SUNBURST" != "null" ]; then
        SUNBURST_MENTIONS=$(echo "$SUNBURST" | jq '.mentions | length')
        echo -e "\n   SUNBURST entity:"
        echo "   - Mentions: $SUNBURST_MENTIONS"
        echo "   - Confidence: $(echo "$SUNBURST" | jq -r '.confidence')%"
        
        if [ "$SUNBURST_MENTIONS" -gt 2 ]; then
          echo "   ✅ Multiple SUNBURST mentions consolidated!"
        fi
      fi
    else
      echo "   ⚠️ No entities extracted"
    fi
    
    # Check techniques
    TECHNIQUES=$(echo "$STATUS_RESPONSE" | jq -r '.result.extraction.techniques // {}')
    TECHNIQUE_COUNT=$(echo "$TECHNIQUES" | jq 'length')
    echo -e "\n6. Techniques extracted: $TECHNIQUE_COUNT"
    
    break
  elif [ "$JOB_STATUS" = "failed" ]; then
    echo -e "\n   ❌ Job failed!"
    ERROR=$(echo "$STATUS_RESPONSE" | jq -r '.error // "Unknown error"')
    echo "   Error: $ERROR"
    break
  fi
done

if [ "$JOB_STATUS" != "completed" ] && [ "$JOB_STATUS" != "failed" ]; then
  echo -e "\n   ⚠️ Job timed out after 5 minutes"
fi

echo -e "\n=========================================="
echo "Integration test complete!"
echo "==========================================" 