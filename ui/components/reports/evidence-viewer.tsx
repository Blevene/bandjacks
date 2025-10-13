import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  FileText,
  Hash,
  BookOpen,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertCircle,
  Eye,
} from 'lucide-react';

interface EvidenceViewerProps {
  nodeId: string;
  nodeType: 'technique' | 'entity';
  nodeName?: string;
  onClose?: () => void;
}

interface TechniqueEvidence {
  report_id: string;
  report_name?: string;
  evidence_texts: string[];
  line_numbers: number[];
  source_summary?: string;
  claim_ids?: string;
  confidence: number;
  technique_name: string;
  technique_id: string;
}

interface EntityEvidence {
  evidence_mentions: string[];
  line_refs: number[];
  source_report: string;
  description?: string;
  confidence: number;
  extraction_metadata?: string;
}

export function EvidenceViewer({
  nodeId,
  nodeType,
  nodeName,
  onClose,
}: EvidenceViewerProps) {
  const [evidence, setEvidence] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedItems, setExpandedItems] = useState<Set<number>>(new Set());

  useEffect(() => {
    fetchEvidence();
  }, [nodeId, nodeType]);

  const fetchEvidence = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `http://localhost:8000/v1/reports/evidence/${nodeId}?node_type=${nodeType}`
      );

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('No evidence found for this node');
        }
        throw new Error('Failed to fetch evidence');
      }

      const data = await response.json();
      setEvidence(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load evidence');
    } finally {
      setLoading(false);
    }
  };

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedItems(newExpanded);
  };

  const renderTechniqueEvidence = () => {
    if (!evidence || !evidence.evidence) return null;

    const records = evidence.evidence as TechniqueEvidence[];

    if (records.length === 0) {
      return (
        <div className="text-center py-8 text-muted-foreground">
          No evidence found for this technique
        </div>
      );
    }

    return (
      <div className="space-y-4">
        {records.map((record, idx) => (
          <Card key={idx}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  <CardTitle className="text-base">
                    {record.report_name || record.report_id}
                  </CardTitle>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">
                    {record.confidence}% confidence
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => toggleExpanded(idx)}
                  >
                    {expandedItems.has(idx) ? (
                      <ChevronUp className="h-4 w-4" />
                    ) : (
                      <ChevronDown className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            </CardHeader>

            {expandedItems.has(idx) && (
              <CardContent className="space-y-3">
                {/* Source Summary */}
                {record.source_summary && (
                  <div className="space-y-1">
                    <div className="text-sm font-medium">Summary:</div>
                    <p className="text-sm text-muted-foreground">
                      {record.source_summary}
                    </p>
                  </div>
                )}

                {/* Evidence Texts */}
                {record.evidence_texts && record.evidence_texts.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-sm font-medium">Evidence:</div>
                    <div className="space-y-2">
                      {record.evidence_texts.map((text, textIdx) => (
                        <div
                          key={textIdx}
                          className="p-3 bg-muted rounded-md text-sm"
                        >
                          <BookOpen className="h-3 w-3 inline mr-2 text-muted-foreground" />
                          {text}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Line References */}
                {record.line_numbers && record.line_numbers.length > 0 && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Hash className="h-3 w-3" />
                    Lines: {record.line_numbers.join(', ')}
                  </div>
                )}

                {/* Claim IDs */}
                {record.claim_ids && (
                  <div className="text-xs text-muted-foreground">
                    Claim IDs: {record.claim_ids}
                  </div>
                )}
              </CardContent>
            )}
          </Card>
        ))}
      </div>
    );
  };

  const renderEntityEvidence = () => {
    if (!evidence || !evidence.evidence) return null;

    const entityEvidence = evidence.evidence as EntityEvidence;

    return (
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>{evidence.entity_name}</CardTitle>
            <div className="flex items-center gap-2 mt-2">
              <Badge>{evidence.entity_type}</Badge>
              <Badge variant="secondary">
                {entityEvidence.confidence}% confidence
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Description */}
            {entityEvidence.description && (
              <div className="space-y-1">
                <div className="text-sm font-medium">Description:</div>
                <p className="text-sm text-muted-foreground">
                  {entityEvidence.description}
                </p>
              </div>
            )}

            {/* Evidence Mentions */}
            {entityEvidence.evidence_mentions &&
              entityEvidence.evidence_mentions.length > 0 && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">Evidence Mentions:</div>
                  <div className="space-y-2">
                    {entityEvidence.evidence_mentions.map((mention, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-muted rounded-md text-sm"
                      >
                        <BookOpen className="h-3 w-3 inline mr-2 text-muted-foreground" />
                        {mention}
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Line References */}
            {entityEvidence.line_refs && entityEvidence.line_refs.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Hash className="h-3 w-3" />
                Lines: {entityEvidence.line_refs.join(', ')}
              </div>
            )}

            {/* Source Report */}
            {entityEvidence.source_report && (
              <div className="text-sm text-muted-foreground">
                <FileText className="h-3 w-3 inline mr-2" />
                Source: {entityEvidence.source_report}
              </div>
            )}

            {/* Extraction Metadata */}
            {entityEvidence.extraction_metadata && (
              <div className="text-xs text-muted-foreground">
                Metadata: {entityEvidence.extraction_metadata}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">
          Evidence for {nodeName || nodeId}
        </h3>
        {onClose && (
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        )}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {!loading && !error && evidence && (
        <ScrollArea className="h-[500px] w-full">
          {nodeType === 'technique'
            ? renderTechniqueEvidence()
            : renderEntityEvidence()}
        </ScrollArea>
      )}
    </div>
  );
}

// Modal wrapper for the evidence viewer
export function EvidenceViewerDialog({
  open,
  onClose,
  nodeId,
  nodeType,
  nodeName,
}: {
  open: boolean;
  onClose: () => void;
  nodeId: string;
  nodeType: 'technique' | 'entity';
  nodeName?: string;
}) {
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[80vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            Evidence Traceback
          </DialogTitle>
          <DialogDescription>
            View the source evidence that substantiated this{' '}
            {nodeType === 'technique' ? 'technique' : 'entity'} from reports
          </DialogDescription>
        </DialogHeader>

        <EvidenceViewer
          nodeId={nodeId}
          nodeType={nodeType}
          nodeName={nodeName}
        />
      </DialogContent>
    </Dialog>
  );
}
