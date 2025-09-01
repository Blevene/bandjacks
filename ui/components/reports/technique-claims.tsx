"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Hash,
  FileText,
  TrendingUp,
  CheckCircle,
  XCircle,
  Edit,
  Eye,
  EyeOff,
} from "lucide-react";
import type { TechniqueClaim } from "@/lib/report-types";
import { getConfidenceColor, getConfidenceBadgeVariant } from "@/lib/report-types";

interface TechniqueClaimsProps {
  claims: TechniqueClaim[];
  reviewMode?: boolean;
  onReviewAction?: (claimIndex: number, action: 'approve' | 'reject' | 'edit') => void;
  reviewedClaims?: Set<number>;
}

export function TechniqueClaims({ 
  claims, 
  reviewMode = false,
  onReviewAction,
  reviewedClaims = new Set()
}: TechniqueClaimsProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [confidenceFilter, setConfidenceFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<'confidence' | 'technique' | 'order'>('confidence');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [expandedClaims, setExpandedClaims] = useState<Set<number>>(new Set());
  const [selectedClaims, setSelectedClaims] = useState<Set<number>>(new Set());

  // Filter and sort claims
  const processedClaims = useMemo(() => {
    let filtered = [...claims];

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(claim => 
        claim.external_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        claim.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        claim.quotes.some(q => q.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    // Apply confidence filter
    if (confidenceFilter !== "all") {
      const threshold = parseInt(confidenceFilter);
      filtered = filtered.filter(claim => {
        if (threshold === 80) return claim.confidence >= 80;
        if (threshold === 50) return claim.confidence >= 50 && claim.confidence < 80;
        if (threshold === 0) return claim.confidence < 50;
        return true;
      });
    }

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'confidence') {
        comparison = a.confidence - b.confidence;
      } else if (sortBy === 'technique') {
        comparison = a.external_id.localeCompare(b.external_id);
      } else {
        comparison = a.span_idx - b.span_idx;
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return filtered.map((claim, index) => ({ ...claim, originalIndex: claims.indexOf(claim) }));
  }, [claims, searchTerm, confidenceFilter, sortBy, sortDirection]);

  // Group claims by technique
  const groupedClaims = useMemo(() => {
    const groups: Record<string, typeof processedClaims> = {};
    processedClaims.forEach(claim => {
      if (!groups[claim.external_id]) {
        groups[claim.external_id] = [];
      }
      groups[claim.external_id].push(claim);
    });
    return groups;
  }, [processedClaims]);

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedClaims);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedClaims(newExpanded);
  };

  const toggleSelected = (index: number) => {
    const newSelected = new Set(selectedClaims);
    if (newSelected.has(index)) {
      newSelected.delete(index);
    } else {
      newSelected.add(index);
    }
    setSelectedClaims(newSelected);
  };

  const selectAll = () => {
    setSelectedClaims(new Set(processedClaims.map(c => c.originalIndex)));
  };

  const deselectAll = () => {
    setSelectedClaims(new Set());
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Technique Claims</CardTitle>
          <CardDescription>
            {claims.length} claims extracted from the document
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4">
            {/* Search and filters */}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search techniques, names, or evidence..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Select value={confidenceFilter} onValueChange={setConfidenceFilter}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="All confidence" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All confidence</SelectItem>
                  <SelectItem value="80">High (≥80%)</SelectItem>
                  <SelectItem value="50">Medium (50-79%)</SelectItem>
                  <SelectItem value="0">Low (&lt;50%)</SelectItem>
                </SelectContent>
              </Select>
              <Select value={sortBy} onValueChange={(v) => setSortBy(v as any)}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="confidence">Confidence</SelectItem>
                  <SelectItem value="technique">Technique ID</SelectItem>
                  <SelectItem value="order">Document Order</SelectItem>
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="icon"
                onClick={() => setSortDirection(d => d === 'asc' ? 'desc' : 'asc')}
              >
                {sortDirection === 'asc' ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>

            {/* Bulk actions for review mode */}
            {reviewMode && (
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={selectAll}>
                  Select All
                </Button>
                <Button variant="outline" size="sm" onClick={deselectAll}>
                  Clear Selection
                </Button>
                {selectedClaims.size > 0 && (
                  <>
                    <span className="text-sm text-muted-foreground">
                      {selectedClaims.size} selected
                    </span>
                    <Button 
                      variant="default" 
                      size="sm"
                      onClick={() => {
                        selectedClaims.forEach(idx => onReviewAction?.(idx, 'approve'));
                      }}
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Approve Selected
                    </Button>
                    <Button 
                      variant="destructive" 
                      size="sm"
                      onClick={() => {
                        selectedClaims.forEach(idx => onReviewAction?.(idx, 'reject'));
                      }}
                    >
                      <XCircle className="h-4 w-4 mr-1" />
                      Reject Selected
                    </Button>
                  </>
                )}
              </div>
            )}

            {/* Summary stats */}
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>Showing {processedClaims.length} of {claims.length} claims</span>
              <span>•</span>
              <span>{Object.keys(groupedClaims).length} unique techniques</span>
              {reviewMode && reviewedClaims.size > 0 && (
                <>
                  <span>•</span>
                  <span>{reviewedClaims.size} reviewed</span>
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Claims list */}
      <ScrollArea className="h-[600px]">
        <div className="space-y-2">
          {processedClaims.map((claim, idx) => {
            const isExpanded = expandedClaims.has(claim.originalIndex);
            const isSelected = selectedClaims.has(claim.originalIndex);
            const isReviewed = reviewedClaims.has(claim.originalIndex);

            return (
              <Card 
                key={`${claim.external_id}-${claim.originalIndex}`}
                className={`transition-colors ${
                  isSelected ? 'border-primary' : ''
                } ${isReviewed ? 'opacity-60' : ''}`}
              >
                <CardContent className="pt-4">
                  <div className="flex items-start gap-3">
                    {/* Selection checkbox */}
                    {reviewMode && (
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => toggleSelected(claim.originalIndex)}
                        className="mt-1"
                      />
                    )}

                    {/* Icon */}
                    <Shield className="h-5 w-5 text-blue-500 mt-1 flex-shrink-0" />

                    {/* Main content */}
                    <div className="flex-1 space-y-2">
                      {/* Header */}
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold">{claim.external_id}</span>
                            <span className="text-sm text-muted-foreground">{claim.name}</span>
                            {claim.source_chunk !== undefined && (
                              <Badge variant="outline" className="text-xs">
                                Chunk {claim.source_chunk}
                              </Badge>
                            )}
                          </div>
                          {claim.technique_meta && (
                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                              {claim.technique_meta.tactic && (
                                <Badge variant="secondary" className="text-xs">
                                  {claim.technique_meta.tactic}
                                </Badge>
                              )}
                              {claim.technique_meta.platforms && claim.technique_meta.platforms.length > 0 && (
                                <span>Platforms: {claim.technique_meta.platforms.join(', ')}</span>
                              )}
                            </div>
                          )}
                        </div>

                        {/* Confidence and actions */}
                        <div className="flex items-center gap-2">
                          <Badge variant={getConfidenceBadgeVariant(claim.confidence)}>
                            <TrendingUp className="h-3 w-3 mr-1" />
                            {claim.confidence}%
                          </Badge>
                          
                          {/* Review actions */}
                          {reviewMode && !isReviewed && (
                            <div className="flex items-center gap-1">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => onReviewAction?.(claim.originalIndex, 'approve')}
                              >
                                <CheckCircle className="h-4 w-4 text-green-500" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => onReviewAction?.(claim.originalIndex, 'reject')}
                              >
                                <XCircle className="h-4 w-4 text-red-500" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => onReviewAction?.(claim.originalIndex, 'edit')}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                            </div>
                          )}

                          {/* Expand toggle */}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => toggleExpanded(claim.originalIndex)}
                          >
                            {isExpanded ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                        </div>
                      </div>

                      {/* Evidence quotes (preview or full) */}
                      <div className="space-y-1">
                        {(isExpanded ? claim.quotes : claim.quotes.slice(0, 1)).map((quote, qIdx) => (
                          <blockquote 
                            key={qIdx}
                            className="border-l-2 border-muted pl-3 text-sm text-muted-foreground italic"
                          >
                            "{quote.length > 200 && !isExpanded ? quote.substring(0, 200) + '...' : quote}"
                          </blockquote>
                        ))}
                        {!isExpanded && claim.quotes.length > 1 && (
                          <button
                            onClick={() => toggleExpanded(claim.originalIndex)}
                            className="text-xs text-blue-500 hover:underline"
                          >
                            +{claim.quotes.length - 1} more quote{claim.quotes.length > 2 ? 's' : ''}
                          </button>
                        )}
                      </div>

                      {/* Additional details when expanded */}
                      {isExpanded && (
                        <div className="pt-2 border-t space-y-2">
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">Evidence Score:</span>
                              <span className="ml-2 font-medium">{claim.evidence_score}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Source:</span>
                              <span className="ml-2 font-medium">{claim.source}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Span Index:</span>
                              <span className="ml-2 font-medium">{claim.span_idx}</span>
                            </div>
                            {claim.line_refs.length > 0 && (
                              <div>
                                <span className="text-muted-foreground">Line References:</span>
                                <span className="ml-2 font-medium">
                                  {claim.line_refs.slice(0, 5).join(', ')}
                                  {claim.line_refs.length > 5 && ` +${claim.line_refs.length - 5} more`}
                                </span>
                              </div>
                            )}
                          </div>
                          {claim.technique_meta?.description && (
                            <div className="text-sm">
                              <span className="text-muted-foreground">Description:</span>
                              <p className="mt-1 text-sm">{claim.technique_meta.description}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}