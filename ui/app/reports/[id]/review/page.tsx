"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Check, X, Edit2, Save, AlertCircle, ChevronLeft, CheckCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Textarea } from "@/components/ui/textarea";
import { typedApi } from "@/lib/api-client";

interface TechniqueClaim {
  technique_id: string;
  technique_name: string;
  confidence: number;
  evidence: {
    quotes: string[];
    line_refs: number[];
  };
  review_action?: "approve" | "reject" | "edit";
  review_notes?: string;
}

interface ReviewData {
  report_id: string;
  review_status: string;
  total_techniques: number;
  reviewed_count: number;
  approved_count: number;
  rejected_count: number;
  edited_count: number;
  extraction_claims: TechniqueClaim[];
}

export default function ReportReviewPage() {
  const params = useParams();
  const router = useRouter();
  const { toast } = useToast();
  const reportId = params.id as string;

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [reviewData, setReviewData] = useState<ReviewData | null>(null);
  const [techniqueActions, setTechniqueActions] = useState<Record<string, {
    action: "approve" | "reject" | "edit";
    notes?: string;
  }>>({});
  const [editingNotes, setEditingNotes] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});

  useEffect(() => {
    if (reportId) {
      fetchReviewData();
    }
  }, [reportId]);

  const fetchReviewData = async () => {
    try {
      const data = await typedApi.reports.getReviewStatus(reportId);
      
      // Transform backend response to match expected structure
      const transformedData: ReviewData = {
        report_id: data.report_id,
        review_status: data.review_status || "pending",
        total_techniques: data.total_claims || 0,
        reviewed_count: 0,
        approved_count: 0,
        rejected_count: 0,
        edited_count: 0,
        extraction_claims: (data.claims || []).map((claim: any) => ({
          technique_id: claim.technique_id,
          technique_name: claim.technique_name,
          confidence: claim.confidence,
          evidence: claim.evidence,
          review_action: claim.review_action,
          review_notes: claim.review_notes
        }))
      };
      
      setReviewData(transformedData);
      
      // Initialize actions from existing review data
      if (transformedData.extraction_claims) {
        const actions: typeof techniqueActions = {};
        transformedData.extraction_claims.forEach((claim: TechniqueClaim) => {
          if (claim.review_action) {
            actions[claim.technique_id] = {
              action: claim.review_action,
              notes: claim.review_notes
            };
            if (claim.review_notes) {
              setNotes(prev => ({ ...prev, [claim.technique_id]: claim.review_notes || "" }));
            }
          }
        });
        setTechniqueActions(actions);
      }
    } catch (error) {
      console.error("Error fetching review data:", error);
      toast({
        title: "Error",
        description: "Failed to load review data",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleAction = (techniqueId: string, action: "approve" | "reject" | "edit") => {
    setTechniqueActions(prev => ({
      ...prev,
      [techniqueId]: {
        action,
        notes: notes[techniqueId]
      }
    }));
  };

  const handleNotesChange = (techniqueId: string, value: string) => {
    setNotes(prev => ({ ...prev, [techniqueId]: value }));
  };

  const handleBulkAction = (action: "approve" | "reject") => {
    if (!reviewData || !reviewData.extraction_claims) return;
    
    const newActions: typeof techniqueActions = {};
    reviewData.extraction_claims.forEach(claim => {
      newActions[claim.technique_id] = { action };
    });
    setTechniqueActions(newActions);
  };

  const handleSubmitReview = async () => {
    if (!reviewData) return;
    
    setSubmitting(true);
    try {
      const techniqueActionsList = Object.entries(techniqueActions).map(([id, data]) => ({
        technique_id: id,
        action: data.action,
        notes: notes[id],
      }));

      await typedApi.reports.submitReview(reportId, {
        reviewer_id: "current-user", // TODO: Get from auth context
        technique_actions: techniqueActionsList,
        overall_notes: "",
      });

      toast({
        title: "Review Submitted",
        description: "Your review has been saved successfully",
      });

      // Refresh data
      await fetchReviewData();
    } catch (error) {
      console.error("Error submitting review:", error);
      toast({
        title: "Error",
        description: "Failed to submit review",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprove = async () => {
    if (!reviewData) return;
    
    setSubmitting(true);
    try {
      const result = await typedApi.reports.approveReport(reportId, {
        reviewer_id: "current-user", // TODO: Get from auth context
        upsert_to_graph: true,
      });
      
      toast({
        title: "Report Approved",
        description: `${result.approved_techniques} techniques have been added to the graph`,
      });

      // Navigate back to report detail
      router.push(`/reports/${reportId}`);
    } catch (error) {
      console.error("Error approving report:", error);
      toast({
        title: "Error",
        description: "Failed to approve report",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const getConfidenceBadge = (confidence: number) => {
    const variant = confidence >= 80 ? "default" : confidence >= 50 ? "secondary" : "destructive";
    const color = confidence >= 80 ? "text-green-600" : confidence >= 50 ? "text-yellow-600" : "text-red-600";
    
    return (
      <Badge variant={variant} className={cn("font-mono", color)}>
        {confidence}%
      </Badge>
    );
  };

  const getActionButton = (techniqueId: string, action: "approve" | "reject" | "edit") => {
    const currentAction = techniqueActions[techniqueId]?.action;
    const isActive = currentAction === action;
    
    const icons = {
      approve: <Check className="h-4 w-4" />,
      reject: <X className="h-4 w-4" />,
      edit: <Edit2 className="h-4 w-4" />,
    };
    
    const colors = {
      approve: "hover:bg-green-100 data-[active=true]:bg-green-500 data-[active=true]:text-white",
      reject: "hover:bg-red-100 data-[active=true]:bg-red-500 data-[active=true]:text-white",
      edit: "hover:bg-blue-100 data-[active=true]:bg-blue-500 data-[active=true]:text-white",
    };
    
    return (
      <Button
        size="sm"
        variant="outline"
        onClick={() => handleAction(techniqueId, action)}
        data-active={isActive}
        className={cn("h-8 w-8 p-0", colors[action])}
      >
        {icons[action]}
      </Button>
    );
  };

  if (loading) {
    return (
      <div className="container mx-auto py-8">
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </div>
    );
  }

  if (!reviewData) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardContent className="py-8">
            <div className="text-center">
              <AlertCircle className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">No review data available</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const approvedCount = Object.values(techniqueActions).filter(a => a.action === "approve").length;
  const rejectedCount = Object.values(techniqueActions).filter(a => a.action === "reject").length;
  const editedCount = Object.values(techniqueActions).filter(a => a.action === "edit").length;

  return (
    <div className="container mx-auto py-8">
      <div className="mb-6">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push(`/reports/${reportId}`)}
          className="mb-4"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back to Report
        </Button>
        
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">Review Extraction Results</h1>
            <p className="text-muted-foreground">
              Review and approve extracted techniques before adding to the knowledge graph
            </p>
          </div>
          
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => handleBulkAction("approve")}
              disabled={submitting}
            >
              Approve All
            </Button>
            <Button
              variant="outline"
              onClick={() => handleBulkAction("reject")}
              disabled={submitting}
            >
              Reject All
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-6 mb-6 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Techniques</CardDescription>
            <CardTitle className="text-2xl">{reviewData.total_techniques || 0}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Approved</CardDescription>
            <CardTitle className="text-2xl text-green-600">{approvedCount}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Rejected</CardDescription>
            <CardTitle className="text-2xl text-red-600">{rejectedCount}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Edited</CardDescription>
            <CardTitle className="text-2xl text-blue-600">{editedCount}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Extracted Techniques</CardTitle>
          <CardDescription>
            Review each technique extraction with evidence and confidence scores
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[150px]">Technique ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead className="w-[100px]">Confidence</TableHead>
                <TableHead>Evidence</TableHead>
                <TableHead className="w-[150px]">Actions</TableHead>
                <TableHead className="w-[200px]">Notes</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(reviewData.extraction_claims || []).map((claim) => (
                <TableRow key={claim.technique_id}>
                  <TableCell className="font-mono text-sm">{claim.technique_id}</TableCell>
                  <TableCell>{claim.technique_name}</TableCell>
                  <TableCell>{getConfidenceBadge(claim.confidence)}</TableCell>
                  <TableCell>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div className="max-w-[300px] truncate text-sm text-muted-foreground cursor-pointer">
                            {claim.evidence.quotes[0]}
                          </div>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-[500px]">
                          <div className="space-y-2">
                            {claim.evidence.quotes.map((quote, idx) => (
                              <div key={idx}>
                                <p className="text-sm">{quote}</p>
                                <p className="text-xs text-muted-foreground">
                                  Line {claim.evidence.line_refs[idx]}
                                </p>
                              </div>
                            ))}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {getActionButton(claim.technique_id, "approve")}
                      {getActionButton(claim.technique_id, "reject")}
                      {getActionButton(claim.technique_id, "edit")}
                    </div>
                  </TableCell>
                  <TableCell>
                    {editingNotes === claim.technique_id ? (
                      <div className="flex gap-1">
                        <Textarea
                          value={notes[claim.technique_id] || ""}
                          onChange={(e) => handleNotesChange(claim.technique_id, e.target.value)}
                          className="h-8 text-sm resize-none"
                          placeholder="Add notes..."
                        />
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setEditingNotes(null)}
                          className="h-8 w-8 p-0"
                        >
                          <Save className="h-4 w-4" />
                        </Button>
                      </div>
                    ) : (
                      <div 
                        className="text-sm text-muted-foreground cursor-pointer hover:text-foreground"
                        onClick={() => setEditingNotes(claim.technique_id)}
                      >
                        {notes[claim.technique_id] || "Click to add notes..."}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="mt-6 flex justify-between">
        <Button
          variant="outline"
          onClick={() => router.push(`/reports/${reportId}`)}
        >
          Cancel
        </Button>
        
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={handleSubmitReview}
            disabled={submitting || Object.keys(techniqueActions).length === 0}
          >
            {submitting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save Review
              </>
            )}
          </Button>
          
          <Button
            onClick={handleApprove}
            disabled={submitting || approvedCount === 0}
          >
            {submitting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Approving...
              </>
            ) : (
              <>
                <CheckCircle className="h-4 w-4 mr-2" />
                Approve & Add to Graph ({approvedCount})
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}