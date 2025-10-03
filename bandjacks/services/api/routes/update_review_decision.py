@router.patch(
    "/{report_id}/review-decision",
    response_model=ReviewDecisionResponse,
    summary="Update Single Review Decision",
    description="Save a single review decision immediately without full submission."
)
async def update_review_decision(
    report_id: str,
    decision: ReviewDecisionUpdate,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Update a single review decision in the report."""

    os_store = OpenSearchReportStore(os_client)

    # Get the report
    report = os_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    # Parse item ID to determine type and index
    item_parts = decision.item_id.split("-")
    if len(item_parts) < 2:
        raise HTTPException(status_code=400, detail=f"Invalid item ID format: {decision.item_id}")

    item_type = item_parts[0]

    try:
        if item_type == "entity":
            # Update entity review status
            if len(item_parts) < 3:
                raise HTTPException(status_code=400, detail=f"Invalid entity ID format: {decision.item_id}")

            entity_type = item_parts[1]
            index = int(item_parts[2])

            entities = report.get("extraction", {}).get("entities", {})
            if isinstance(entities, dict) and "entities" in entities:
                entity_list = entities.get("entities", [])
                if index < len(entity_list):
                    entity = entity_list[index]
                    entity["review_status"] = decision.action
                    if decision.notes:
                        entity["review_notes"] = decision.notes
                    if decision.edited_value:
                        entity.update(decision.edited_value)
                    if decision.confidence_adjustment is not None:
                        entity["confidence"] = decision.confidence_adjustment
                else:
                    raise HTTPException(status_code=404, detail=f"Entity index {index} not found")
            else:
                raise HTTPException(status_code=404, detail="No entities found in report")

        elif item_type == "technique":
            # Update technique review status
            index = int(item_parts[1])
            claims = report.get("extraction", {}).get("claims", [])

            if index < len(claims):
                claim = claims[index]
                claim["review_status"] = decision.action
                if decision.notes:
                    claim["review_notes"] = decision.notes
                if decision.confidence_adjustment is not None:
                    claim["confidence"] = decision.confidence_adjustment
                if decision.edited_value:
                    if "external_id" in decision.edited_value:
                        claim["external_id"] = decision.edited_value["external_id"]
                    if "name" in decision.edited_value:
                        claim["name"] = decision.edited_value["name"]
            else:
                raise HTTPException(status_code=404, detail=f"Technique index {index} not found")

        elif item_type == "flow":
            # Update flow step review status
            step_id = "-".join(item_parts[1:])
            flow_steps = report.get("extraction", {}).get("flow", {}).get("steps", [])

            step_found = False
            for step in flow_steps:
                # Check both step_id and action_id (different field names in different versions)
                if step.get("step_id") == step_id or step.get("action_id") == step_id:
                    step["review_status"] = decision.action
                    if decision.notes:
                        step["review_notes"] = decision.notes
                    if decision.edited_value:
                        step.update(decision.edited_value)
                    step_found = True
                    break

            if not step_found:
                # Log available step IDs for debugging
                available_ids = [f"{step.get('action_id', step.get('step_id', 'no-id'))}" for step in flow_steps]
                logger.error(f"Flow step {step_id} not found. Available: {available_ids}")
                raise HTTPException(status_code=404, detail=f"Flow step {step_id} not found")

        else:
            raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")

        # Update the report in OpenSearch
        update_doc = {
            "doc": {
                "extraction": report.get("extraction", {}),
                "modified": datetime.utcnow().isoformat()
            }
        }

        os_client.update(
            index="bandjacks_reports",
            id=report_id,
            body=update_doc
        )

        logger.info(f"Updated review decision for {decision.item_id} in report {report_id}")

        return ReviewDecisionResponse(
            success=True,
            message=f"Review decision saved for {decision.item_id}",
            updated_item_id=decision.item_id
        )

    except Exception as e:
        logger.error(f"Failed to update review decision for {report_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save review decision: {str(e)}"
        )