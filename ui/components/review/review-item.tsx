"use client";

import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { UncertaintyQueueItem } from "@/lib/simulation-types";
import { Check, X, Edit, MessageSquare, AlertTriangle, Clock } from "lucide-react";

interface ReviewItemProps {
  item: UncertaintyQueueItem;
  onDecision: (
    queueId: string,
    decision: "accept" | "edit" | "reject",
    notes?: string,
    updatedValue?: any
  ) => void;
}

const itemTypeColors = {
  flow_edge: "bg-blue-100 text-blue-800",
  mapping: "bg-green-100 text-green-800",
  extraction: "bg-purple-100 text-purple-800",
  detection: "bg-orange-100 text-orange-800",
};

export function ReviewItem({ item, onDecision }: ReviewItemProps) {
  const [showDetails, setShowDetails] = useState(false);
  const [editing, setEditing] = useState(false);
  const [notes, setNotes] = useState("");
  const [editedValue, setEditedValue] = useState(
    typeof item.proposed_value === "string" 
      ? item.proposed_value 
      : JSON.stringify(item.proposed_value, null, 2)
  );

  const handleAccept = () => {
    onDecision(item.queue_id, "accept", notes || undefined);
  };

  const handleReject = () => {
    onDecision(item.queue_id, "reject", notes || undefined);
  };

  const handleEdit = () => {
    try {
      const updatedValue = editedValue.startsWith("{") || editedValue.startsWith("[")
        ? JSON.parse(editedValue)
        : editedValue;
      onDecision(item.queue_id, "edit", notes || undefined, updatedValue);
    } catch (err) {
      alert("Invalid JSON format");
    }
  };

  const confidencePercent = (item.confidence * 100).toFixed(0);
  const uncertaintyPercent = (item.uncertainty_score * 100).toFixed(0);

  return (
    <Card className="p-4">
      <div className="space-y-3">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <Badge className={itemTypeColors[item.item_type]}>
              {item.item_type.replace("_", " ")}
            </Badge>
            <Badge variant="outline">
              <AlertTriangle className="h-3 w-3 mr-1" />
              {confidencePercent}% confidence
            </Badge>
            <Badge variant="secondary">
              Priority: {item.priority.toFixed(0)}
            </Badge>
            {item.age_hours && (
              <Badge variant="outline">
                <Clock className="h-3 w-3 mr-1" />
                {item.age_hours}h old
              </Badge>
            )}
          </div>
          
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowDetails(!showDetails)}
          >
            {showDetails ? "Hide" : "Show"} Context
          </Button>
        </div>

        {/* Context Display */}
        <div className="bg-muted/50 rounded-md p-3">
          {renderContext(item)}
        </div>

        {/* Proposed Value */}
        {item.proposed_value !== undefined && (
          <div>
            <label className="text-sm font-medium mb-1 block">Proposed Value:</label>
            {editing ? (
              <textarea
                className="w-full px-3 py-2 border rounded-md font-mono text-sm"
                rows={4}
                value={editedValue}
                onChange={(e) => setEditedValue(e.target.value)}
              />
            ) : (
              <div className="bg-muted/30 rounded-md p-3 font-mono text-sm">
                {typeof item.proposed_value === "string" 
                  ? item.proposed_value 
                  : JSON.stringify(item.proposed_value, null, 2)}
              </div>
            )}
          </div>
        )}

        {/* Extended Context */}
        {showDetails && item.source_context && (
          <div className="border-t pt-3">
            <h4 className="text-sm font-medium mb-2">Full Context:</h4>
            <pre className="text-xs bg-muted/30 rounded-md p-3 overflow-x-auto">
              {JSON.stringify(item.source_context, null, 2)}
            </pre>
          </div>
        )}

        {/* Notes */}
        <div>
          <label className="text-sm font-medium mb-1 block">
            <MessageSquare className="h-3 w-3 inline mr-1" />
            Review Notes (Optional):
          </label>
          <textarea
            className="w-full px-3 py-2 border rounded-md text-sm"
            rows={2}
            placeholder="Add notes about your decision..."
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 pt-2">
          <Button onClick={handleAccept} variant="default" size="sm">
            <Check className="h-4 w-4 mr-1" />
            Accept
          </Button>
          
          {editing ? (
            <Button onClick={handleEdit} variant="outline" size="sm">
              <Check className="h-4 w-4 mr-1" />
              Save Edit
            </Button>
          ) : (
            <Button onClick={() => setEditing(true)} variant="outline" size="sm">
              <Edit className="h-4 w-4 mr-1" />
              Edit
            </Button>
          )}
          
          <Button onClick={handleReject} variant="destructive" size="sm">
            <X className="h-4 w-4 mr-1" />
            Reject
          </Button>
          
          {editing && (
            <Button onClick={() => setEditing(false)} variant="ghost" size="sm">
              Cancel
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

function renderContext(item: UncertaintyQueueItem) {
  const context = item.source_context;
  
  switch (item.item_type) {
    case "flow_edge":
      return (
        <div className="space-y-1">
          <div className="text-sm">
            <span className="font-medium">Flow Edge:</span> {context.source} → {context.target}
          </div>
          {context.flow_id && (
            <div className="text-xs text-muted-foreground">Flow ID: {context.flow_id}</div>
          )}
          {context.probability !== undefined && (
            <div className="text-xs text-muted-foreground">
              Probability: {(context.probability * 100).toFixed(1)}%
            </div>
          )}
        </div>
      );
      
    case "mapping":
      return (
        <div className="space-y-1">
          <div className="text-sm">
            <span className="font-medium">Mapping:</span> "{context.source_text}"
          </div>
          <div className="text-xs text-muted-foreground">
            → {context.technique_id}: {context.technique_name}
          </div>
        </div>
      );
      
    case "extraction":
      return (
        <div className="space-y-1">
          <div className="text-sm">
            <span className="font-medium">Extraction:</span> {context.entity_type}
          </div>
          <div className="text-xs text-muted-foreground">
            Value: {context.extracted_value}
          </div>
          {context.source_doc && (
            <div className="text-xs text-muted-foreground">
              Source: {context.source_doc}
            </div>
          )}
        </div>
      );
      
    case "detection":
      return (
        <div className="space-y-1">
          <div className="text-sm">
            <span className="font-medium">Detection:</span> {context.strategy_name}
          </div>
          <div className="text-xs text-muted-foreground">
            Detects: {context.technique_id} - {context.technique_name}
          </div>
        </div>
      );
      
    default:
      return (
        <div className="text-sm text-muted-foreground">
          {JSON.stringify(context)}
        </div>
      );
  }
}