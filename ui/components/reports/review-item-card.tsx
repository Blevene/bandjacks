"use client";

import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Shield,
  Users,
  Bug,
  Target,
  GitBranch,
  CheckCircle,
  XCircle,
  Edit,
  ChevronDown,
  ChevronUp,
  Hash,
  FileText,
  TrendingUp,
  Wrench,
} from "lucide-react";
import type { ReviewableItem, UnifiedReviewDecision } from "@/lib/report-types";

interface ReviewItemCardProps {
  item: ReviewableItem;
  isSelected?: boolean;
  isExpanded?: boolean;
  onSelect?: (selected: boolean) => void;
  onExpand?: (expanded: boolean) => void;
  onReviewAction?: (action: 'approve' | 'reject' | 'edit') => void;
  onEditSave?: (editedItem: Partial<ReviewableItem>) => void;
  readOnly?: boolean;
}

export function ReviewItemCard({
  item,
  isSelected = false,
  isExpanded = false,
  onSelect,
  onExpand,
  onReviewAction,
  onEditSave,
  readOnly = false,
}: ReviewItemCardProps) {
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editedName, setEditedName] = useState(item.name);
  const [editedConfidence, setEditedConfidence] = useState(item.confidence);
  const [editNotes, setEditNotes] = useState(item.review_notes || "");

  const getIcon = () => {
    if (item.type === 'entity') {
      switch (item.category?.toLowerCase()) {
        case 'malware':
          return <Bug className="h-4 w-4" />;
        case 'software':
        case 'tool':
          return <Wrench className="h-4 w-4" />;
        case 'threat actors':
        case 'threat_actor':
          return <Users className="h-4 w-4" />;
        case 'campaigns':
        case 'campaign':
          return <Target className="h-4 w-4" />;
        default:
          return <Shield className="h-4 w-4" />;
      }
    } else if (item.type === 'technique') {
      return <Shield className="h-4 w-4 text-blue-500" />;
    } else if (item.type === 'flow_step') {
      return <GitBranch className="h-4 w-4 text-purple-500" />;
    }
    return <FileText className="h-4 w-4" />;
  };

  const getStatusBadge = () => {
    switch (item.review_status) {
      case 'approved':
        return <Badge variant="default" className="bg-green-500">Approved</Badge>;
      case 'rejected':
        return <Badge variant="destructive">Rejected</Badge>;
      case 'edited':
        return <Badge variant="secondary">Edited</Badge>;
      default:
        return <Badge variant="outline">Pending</Badge>;
    }
  };

  const getTypeBadge = () => {
    const typeLabels = {
      entity: item.category || 'Entity',
      technique: 'Technique',
      flow_step: 'Flow Step',
    };
    
    return (
      <Badge variant="outline" className="text-xs">
        {typeLabels[item.type]}
      </Badge>
    );
  };

  const handleEdit = () => {
    setEditDialogOpen(true);
  };

  const handleEditSave = () => {
    onEditSave?.({
      name: editedName,
      confidence: editedConfidence,
      review_notes: editNotes,
      review_status: 'edited',
    });
    setEditDialogOpen(false);
    onReviewAction?.('edit');
  };

  const isReviewed = item.review_status && item.review_status !== 'pending';

  return (
    <>
      <Card className={`transition-all ${isSelected ? 'ring-2 ring-primary' : ''} ${isReviewed ? 'opacity-75' : ''}`}>
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            {/* Selection checkbox */}
            {!readOnly && (
              <Checkbox
                checked={isSelected}
                onCheckedChange={(checked) => onSelect?.(checked as boolean)}
                className="mt-1"
              />
            )}

            {/* Icon */}
            <div className="mt-1">{getIcon()}</div>

            {/* Main content */}
            <div className="flex-1 space-y-2">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    {/* For techniques, split the ID and name for better display */}
                    {item.type === 'technique' && item.technique_id ? (
                      <>
                        <Badge variant="outline" className="text-xs font-mono">
                          {item.technique_id}
                        </Badge>
                        <span className="font-medium">
                          {item.name.replace(`${item.technique_id}: `, '')}
                        </span>
                      </>
                    ) : (
                      <span className="font-medium">{item.name}</span>
                    )}
                    {getTypeBadge()}
                  </div>
                  
                  {/* Metadata */}
                  {item.type === 'entity' && item.metadata.aliases?.length > 0 && (
                    <p className="text-xs text-muted-foreground">
                      Also known as: {item.metadata.aliases.join(', ')}
                    </p>
                  )}
                  
                  {item.type === 'technique' && item.metadata.technique_meta?.tactic && (
                    <Badge variant="secondary" className="text-xs">
                      {item.metadata.technique_meta.tactic}
                    </Badge>
                  )}
                  
                  {item.type === 'flow_step' && (
                    <p className="text-xs text-muted-foreground">
                      Step {item.metadata.order}
                    </p>
                  )}
                </div>

                {/* Actions and status */}
                <div className="flex items-center gap-2">
                  {/* Confidence badge */}
                  <Badge 
                    variant={item.confidence >= 80 ? 'default' : item.confidence >= 50 ? 'secondary' : 'destructive'}
                  >
                    <TrendingUp className="h-3 w-3 mr-1" />
                    {Math.round(item.confidence)}%
                  </Badge>

                  {/* Review status */}
                  {getStatusBadge()}

                  {/* Review actions */}
                  {!readOnly && !isReviewed && (
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onReviewAction?.('approve')}
                      >
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onReviewAction?.('reject')}
                      >
                        <XCircle className="h-4 w-4 text-red-500" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={handleEdit}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                    </div>
                  )}

                  {/* Expand toggle */}
                  {item.evidence.length > 0 && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => onExpand?.(!isExpanded)}
                    >
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </Button>
                  )}
                </div>
              </div>

              {/* Evidence (preview or full) */}
              {item.evidence.length > 0 && (
                <div className="space-y-1">
                  {/* For entities with mentions metadata, show enhanced evidence */}
                  {item.type === 'entity' && item.metadata.mentions?.length > 0 ? (
                    (isExpanded ? item.metadata.mentions : item.metadata.mentions.slice(0, 1)).map((mention: any, idx: number) => (
                      <div key={idx} className="space-y-1">
                        <blockquote className="border-l-2 border-muted pl-3 text-sm text-muted-foreground italic">
                          "{mention.quote.length > 200 && !isExpanded ? mention.quote.substring(0, 200) + '...' : mention.quote}"
                        </blockquote>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground pl-3">
                          {mention.line_refs && mention.line_refs.length > 0 && (
                            <span>Lines: {mention.line_refs.slice(0, 3).join(', ')}{mention.line_refs.length > 3 && '...'}</span>
                          )}
                          {mention.context && (
                            <Badge variant="outline" className="text-xs">
                              {mention.context === 'primary_mention' ? 'Primary' : 
                               mention.context === 'alias' ? 'Alias' : 
                               'Reference'}
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))
                  ) : (
                    // Default evidence display for techniques and legacy entities
                    item.evidence && Array.isArray(item.evidence) && item.evidence.length > 0 ? (
                      (isExpanded ? item.evidence : item.evidence.slice(0, 1)).map((evidence, idx) => {
                        const evidenceText = typeof evidence === 'string' 
                          ? evidence 
                          : (evidence as any).text || '';
                        
                        return (
                          <blockquote
                            key={idx}
                            className="border-l-2 border-muted pl-3 text-sm text-muted-foreground italic"
                          >
                            "{evidenceText.length > 200 && !isExpanded ? evidenceText.substring(0, 200) + '...' : evidenceText}"
                          </blockquote>
                        );
                      })
                    ) : (
                      <span className="text-sm text-muted-foreground italic">No evidence available</span>
                    )
                  )}
                  
                  {/* Show more evidence button */}
                  {!isExpanded && (
                    (item.type === 'entity' && item.metadata.mentions?.length > 1) ? (
                      <button
                        onClick={() => onExpand?.(true)}
                        className="text-xs text-blue-500 hover:underline"
                      >
                        +{item.metadata.mentions.length - 1} more mentions
                      </button>
                    ) : (
                      item.evidence && Array.isArray(item.evidence) && item.evidence.length > 1 && (
                        <button
                          onClick={() => onExpand?.(true)}
                          className="text-xs text-blue-500 hover:underline"
                        >
                          +{item.evidence.length - 1} more evidence
                        </button>
                      )
                    )
                  )}
                </div>
              )}

              {/* Additional details when expanded */}
              {isExpanded && (
                <div className="pt-2 border-t space-y-2">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    {item.line_refs && item.line_refs.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Line References:</span>
                        <span className="ml-2 font-medium">
                          {item.line_refs.slice(0, 5).join(', ')}
                          {item.line_refs.length > 5 && ` +${item.line_refs.length - 5} more`}
                        </span>
                      </div>
                    )}
                    
                    {item.type === 'technique' && (
                      <>
                        <div>
                          <span className="text-muted-foreground">Source:</span>
                          <span className="ml-2 font-medium">{item.metadata.source}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Evidence Score:</span>
                          <span className="ml-2 font-medium">{item.metadata.evidence_score}</span>
                        </div>
                      </>
                    )}
                    
                    {item.metadata.description && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Description:</span>
                        <p className="mt-1 text-sm">{item.metadata.description}</p>
                      </div>
                    )}
                  </div>
                  
                  {item.review_notes && (
                    <div className="text-sm">
                      <span className="text-muted-foreground">Review Notes:</span>
                      <p className="mt-1 italic">{item.review_notes}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Edit {item.type === 'entity' ? 'Entity' : item.type === 'technique' ? 'Technique' : 'Flow Step'}</DialogTitle>
            <DialogDescription>
              Make changes to the extracted information.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={editedName}
                onChange={(e) => setEditedName(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="confidence">Confidence (%)</Label>
              <Input
                id="confidence"
                type="number"
                min="0"
                max="100"
                value={editedConfidence}
                onChange={(e) => setEditedConfidence(Number(e.target.value))}
              />
            </div>
            <div>
              <Label htmlFor="notes">Review Notes</Label>
              <Textarea
                id="notes"
                value={editNotes}
                onChange={(e) => setEditNotes(e.target.value)}
                placeholder="Add any notes about this change..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleEditSave}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}