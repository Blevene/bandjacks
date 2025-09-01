"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  FileText,
  Hash,
  Quote,
  Eye,
  EyeOff,
  Maximize2,
  Minimize2,
  FileCode,
  AlignLeft,
} from "lucide-react";
import type { TechniqueClaim } from "@/lib/report-types";
import { getConfidenceColor, getConfidenceBadgeVariant } from "@/lib/report-types";

interface EvidenceViewerProps {
  claims: TechniqueClaim[];
  reportText?: string;
}

export function EvidenceViewer({ claims, reportText }: EvidenceViewerProps) {
  const [showLineNumbers, setShowLineNumbers] = useState(true);
  const [showContext, setShowContext] = useState(true);
  const [contextLines, setContextLines] = useState([3]);
  const [expandedView, setExpandedView] = useState(false);
  const [highlightedClaim, setHighlightedClaim] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<'by-technique' | 'by-document'>('by-technique');

  // Group claims by technique
  const claimsByTechnique = useMemo(() => {
    const groups: Record<string, TechniqueClaim[]> = {};
    claims.forEach(claim => {
      if (!groups[claim.external_id]) {
        groups[claim.external_id] = [];
      }
      groups[claim.external_id].push(claim);
    });
    return groups;
  }, [claims]);

  // Group claims by source chunk for document order
  const claimsByChunk = useMemo(() => {
    const groups: Record<number, TechniqueClaim[]> = {};
    claims.forEach(claim => {
      const chunk = claim.source_chunk ?? -1;
      if (!groups[chunk]) {
        groups[chunk] = [];
      }
      groups[chunk].push(claim);
    });
    // Sort each chunk's claims by span_idx
    Object.values(groups).forEach(chunkClaims => {
      chunkClaims.sort((a, b) => a.span_idx - b.span_idx);
    });
    return groups;
  }, [claims]);

  // Get all unique line references
  const allLineRefs = useMemo(() => {
    const refs = new Set<number>();
    claims.forEach(claim => {
      claim.line_refs.forEach(ref => refs.add(ref));
    });
    return Array.from(refs).sort((a, b) => a - b);
  }, [claims]);

  const renderEvidence = (claim: TechniqueClaim, index: number) => {
    const isHighlighted = highlightedClaim === index;

    return (
      <Card 
        key={`${claim.external_id}-${index}`}
        className={`transition-all ${isHighlighted ? 'ring-2 ring-primary' : ''}`}
        onMouseEnter={() => setHighlightedClaim(index)}
        onMouseLeave={() => setHighlightedClaim(null)}
      >
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant="outline">{claim.external_id}</Badge>
                <span className="text-sm font-medium">{claim.name}</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span>Span {claim.span_idx}</span>
                {claim.source_chunk !== undefined && (
                  <>
                    <span>•</span>
                    <span>Chunk {claim.source_chunk}</span>
                  </>
                )}
                {claim.line_refs.length > 0 && (
                  <>
                    <span>•</span>
                    <span>Lines {claim.line_refs[0]}-{claim.line_refs[claim.line_refs.length - 1]}</span>
                  </>
                )}
              </div>
            </div>
            <Badge variant={getConfidenceBadgeVariant(claim.confidence)}>
              {claim.confidence}%
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Evidence quotes */}
          {claim.quotes.map((quote, qIdx) => (
            <div key={qIdx} className="space-y-2">
              <div className="flex items-start gap-2">
                <Quote className="h-4 w-4 text-muted-foreground mt-1 flex-shrink-0" />
                <blockquote className="flex-1 text-sm italic">
                  "{quote}"
                </blockquote>
              </div>
              
              {/* Line references with context */}
              {showContext && claim.line_refs.length > 0 && qIdx === 0 && (
                <div className="ml-6 mt-2">
                  <div className="bg-muted/30 rounded-md p-3 font-mono text-xs">
                    {showLineNumbers && (
                      <div className="space-y-1">
                        {claim.line_refs.slice(0, 5).map(lineNum => (
                          <div key={lineNum} className="flex">
                            <span className="text-muted-foreground mr-3 select-none">
                              {String(lineNum).padStart(4, ' ')}
                            </span>
                            <span className="text-foreground">
                              {/* This would show actual line content if we had it */}
                              [Line {lineNum} content would appear here]
                            </span>
                          </div>
                        ))}
                        {claim.line_refs.length > 5 && (
                          <div className="text-muted-foreground">
                            ... and {claim.line_refs.length - 5} more lines
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}

          {/* Evidence metadata */}
          <div className="flex items-center gap-4 pt-2 border-t text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Hash className="h-3 w-3" />
              <span>Evidence Score: {claim.evidence_score}</span>
            </div>
            <div className="flex items-center gap-1">
              <FileCode className="h-3 w-3" />
              <span>Source: {claim.source}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Evidence Viewer</CardTitle>
          <CardDescription>
            Detailed evidence and context for {claims.length} extracted claims
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* View controls */}
            <div className="flex items-center justify-between">
              <Tabs value={viewMode} onValueChange={(v) => setViewMode(v as any)}>
                <TabsList>
                  <TabsTrigger value="by-technique">
                    By Technique ({Object.keys(claimsByTechnique).length})
                  </TabsTrigger>
                  <TabsTrigger value="by-document">
                    Document Order ({Object.keys(claimsByChunk).length} chunks)
                  </TabsTrigger>
                </TabsList>
              </Tabs>

              <Button
                variant="outline"
                size="sm"
                onClick={() => setExpandedView(!expandedView)}
              >
                {expandedView ? (
                  <>
                    <Minimize2 className="h-4 w-4 mr-1" />
                    Collapse
                  </>
                ) : (
                  <>
                    <Maximize2 className="h-4 w-4 mr-1" />
                    Expand
                  </>
                )}
              </Button>
            </div>

            {/* Display options */}
            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="line-numbers"
                  checked={showLineNumbers}
                  onCheckedChange={setShowLineNumbers}
                />
                <Label htmlFor="line-numbers" className="text-sm">
                  Show line numbers
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="show-context"
                  checked={showContext}
                  onCheckedChange={setShowContext}
                />
                <Label htmlFor="show-context" className="text-sm">
                  Show context
                </Label>
              </div>

              {showContext && (
                <div className="flex items-center space-x-2">
                  <Label htmlFor="context-lines" className="text-sm">
                    Context lines: {contextLines[0]}
                  </Label>
                  <Slider
                    id="context-lines"
                    min={1}
                    max={10}
                    step={1}
                    value={contextLines}
                    onValueChange={setContextLines}
                    className="flex-1"
                  />
                </div>
              )}
            </div>

            {/* Statistics */}
            <div className="flex items-center gap-6 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <FileText className="h-4 w-4" />
                <span>{claims.length} total claims</span>
              </div>
              <div className="flex items-center gap-1">
                <AlignLeft className="h-4 w-4" />
                <span>{allLineRefs.length} unique lines referenced</span>
              </div>
              <div className="flex items-center gap-1">
                <Quote className="h-4 w-4" />
                <span>{claims.reduce((sum, c) => sum + c.quotes.length, 0)} evidence quotes</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Evidence display */}
      <ScrollArea className={expandedView ? "h-[800px]" : "h-[600px]"}>
        <div className="space-y-4">
          {viewMode === 'by-technique' ? (
            // Group by technique
            Object.entries(claimsByTechnique)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([techniqueId, techniqueClaims]) => (
                <div key={techniqueId} className="space-y-2">
                  <div className="sticky top-0 bg-background z-10 py-2">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Badge>{techniqueId}</Badge>
                      <span className="text-sm text-muted-foreground">
                        {techniqueClaims[0].name} ({techniqueClaims.length} claims)
                      </span>
                    </h3>
                  </div>
                  <div className="space-y-2">
                    {techniqueClaims.map((claim, idx) => 
                      renderEvidence(claim, claims.indexOf(claim))
                    )}
                  </div>
                </div>
              ))
          ) : (
            // Group by document order (chunks)
            Object.entries(claimsByChunk)
              .sort(([a], [b]) => Number(a) - Number(b))
              .map(([chunkId, chunkClaims]) => (
                <div key={chunkId} className="space-y-2">
                  <div className="sticky top-0 bg-background z-10 py-2">
                    <h3 className="text-lg font-semibold">
                      {chunkId === '-1' ? 'Unchunked' : `Chunk ${chunkId}`}
                      <span className="ml-2 text-sm text-muted-foreground">
                        ({chunkClaims.length} claims)
                      </span>
                    </h3>
                  </div>
                  <div className="space-y-2">
                    {chunkClaims.map((claim, idx) => 
                      renderEvidence(claim, claims.indexOf(claim))
                    )}
                  </div>
                </div>
              ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}