"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { 
  Loader2, 
  Check, 
  X, 
  Edit2, 
  Save, 
  AlertCircle, 
  ChevronLeft, 
  CheckCircle,
  Shield,
  TrendingUp,
  Eye,
  EyeOff
} from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { Report, TechniqueClaim, ClaimReviewDecision } from "@/lib/report-types";
import { getConfidenceColor, getConfidenceBadgeVariant, isExtractionComplete } from "@/lib/report-types";
import { TechniqueClaims } from "@/components/reports/technique-claims";

export default function ReportReviewPage() {
  const params = useParams();
  const router = useRouter();
  const reportId = params.id as string;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [reviewDecisions, setReviewDecisions] = useState<Record<number, ClaimReviewDecision>>({});
  const [reviewNotes, setReviewNotes] = useState("");
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editingClaim, setEditingClaim] = useState<{ index: number; claim: TechniqueClaim } | null>(null);
  const [editedTechniqueId, setEditedTechniqueId] = useState("");
  const [editedConfidence, setEditedConfidence] = useState(0);
  const { toast } = useToast();

  useEffect(() => {
    if (reportId) {
      fetchReport();
    }
  }, [reportId]);

  const fetchReport = async () => {
    try {
      const response = await fetch(`http://localhost:8000/v1/reports/${reportId}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch report: ${response.statusText}`);
      }
      const data = await response.json();
      setReport(data);

      // Initialize review decisions from existing review data
      if (data.review?.decisions) {
        const decisions: Record<number, ClaimReviewDecision> = {};
        Object.entries(data.review.decisions).forEach(([techId, decision]: [string, any]) => {
          // Map existing decisions to claim indices
          data.extraction?.claims?.forEach((claim: TechniqueClaim, idx: number) => {
            if (claim.external_id === techId) {
              decisions[idx] = {
                claim_index: idx,
                technique_id: techId,
                action: decision.action,
                edited_technique_id: decision.edited_mapping,
                confidence_adjustment: decision.confidence,
                notes: decision.notes
              };
            }
          });
        });
        setReviewDecisions(decisions);
      }
    } catch (error: any) {
      console.error("Error fetching report:", error);
      toast({
        title: "Error loading report",
        description: error.message || "Failed to load report for review",
        variant: "destructive",
      });
      setTimeout(() => router.push("/reports"), 2000);
    } finally {
      setLoading(false);
    }
  };

  const handleReviewAction = (claimIndex: number, action: 'approve' | 'reject' | 'edit') => {
    if (action === 'edit') {
      const claim = report?.extraction?.claims[claimIndex];
      if (claim) {
        setEditingClaim({ index: claimIndex, claim });
        setEditedTechniqueId(claim.external_id);
        setEditedConfidence(claim.confidence);
        setEditDialogOpen(true);
      }
    } else {
      setReviewDecisions(prev => ({
        ...prev,
        [claimIndex]: {
          claim_index: claimIndex,
          technique_id: report?.extraction?.claims[claimIndex]?.external_id || '',
          action: action,
          notes: ''
        }
      }));
    }
  };

  const handleEditSave = () => {
    if (editingClaim) {
      setReviewDecisions(prev => ({
        ...prev,
        [editingClaim.index]: {
          claim_index: editingClaim.index,
          technique_id: editingClaim.claim.external_id,
          action: 'edit',
          edited_technique_id: editedTechniqueId !== editingClaim.claim.external_id ? editedTechniqueId : undefined,
          confidence_adjustment: editedConfidence !== editingClaim.claim.confidence ? editedConfidence : undefined,
          notes: ''
        }
      }));
      setEditDialogOpen(false);
      setEditingClaim(null);
    }
  };

  const handleSubmitReview = async () => {
    if (!report || !isExtractionComplete(report)) return;

    setSaving(true);
    try {
      const response = await fetch(`http://localhost:8000/v1/reports/${reportId}/review`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          reviewer_id: 'user-001', // TODO: Get from auth context
          decisions: Object.values(reviewDecisions),
          notes: reviewNotes
        })
      });

      if (!response.ok) {
        throw new Error('Failed to submit review');
      }

      toast({
        title: "Review submitted",
        description: `Successfully reviewed ${Object.keys(reviewDecisions).length} claims`,
      });

      router.push(`/reports/${reportId}`);
    } catch (error: any) {
      console.error("Error submitting review:", error);
      toast({
        title: "Error submitting review",
        description: error.message || "Failed to save review decisions",
        variant: "destructive",
      });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!report || !isExtractionComplete(report)) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
        <p className="text-lg font-medium">No extraction to review</p>
        <p className="text-sm text-muted-foreground mt-2">
          This report doesn't have extraction results to review
        </p>
        <Button
          className="mt-4"
          onClick={() => router.push(`/reports/${reportId}`)}
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Back to Report
        </Button>
      </div>
    );
  }

  const extraction = report.extraction!;
  const reviewedCount = Object.keys(reviewDecisions).length;
  const approvedCount = Object.values(reviewDecisions).filter(d => d.action === 'approve').length;
  const rejectedCount = Object.values(reviewDecisions).filter(d => d.action === 'reject').length;
  const editedCount = Object.values(reviewDecisions).filter(d => d.action === 'edit').length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.push(`/reports/${reportId}`)}
            className="mb-2"
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Back to Report
          </Button>
          <h1 className="text-3xl font-bold tracking-tight">
            Review Extraction Results
          </h1>
          <p className="text-muted-foreground mt-2">
            {report.name}
          </p>
        </div>
        <div className="text-right">
          <Badge variant={report.status === 'pending_review' ? 'secondary' : 'default'}>
            {report.status.replace('_', ' ').toUpperCase()}
          </Badge>
        </div>
      </div>

      {/* Review Progress */}
      <Card>
        <CardHeader>
          <CardTitle>Review Progress</CardTitle>
          <CardDescription>
            Track your review decisions across all extracted claims
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold">{extraction.claims_count}</p>
              <p className="text-xs text-muted-foreground">Total Claims</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{reviewedCount}</p>
              <p className="text-xs text-muted-foreground">Reviewed</p>
              <div className="mt-1 w-full bg-secondary rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full transition-all"
                  style={{ width: `${(reviewedCount / extraction.claims_count) * 100}%` }}
                />
              </div>
            </div>
            <div>
              <p className="text-2xl font-bold text-green-500">{approvedCount}</p>
              <p className="text-xs text-muted-foreground">Approved</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-red-500">{rejectedCount}</p>
              <p className="text-xs text-muted-foreground">Rejected</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-yellow-500">{editedCount}</p>
              <p className="text-xs text-muted-foreground">Edited</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Claims Review Interface */}
      <Card>
        <CardHeader>
          <CardTitle>Technique Claims</CardTitle>
          <CardDescription>
            Review each claim and its supporting evidence
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TechniqueClaims
            claims={extraction.claims}
            reviewMode={true}
            onReviewAction={handleReviewAction}
            reviewedClaims={new Set(Object.keys(reviewDecisions).map(k => parseInt(k)))}
          />
        </CardContent>
      </Card>

      {/* Review Notes */}
      <Card>
        <CardHeader>
          <CardTitle>Review Notes</CardTitle>
          <CardDescription>
            Add any additional notes about this review
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            placeholder="Enter any additional notes about your review decisions..."
            value={reviewNotes}
            onChange={(e) => setReviewNotes(e.target.value)}
            className="min-h-[100px]"
          />
        </CardContent>
      </Card>

      {/* Submit Actions */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {reviewedCount > 0 ? (
            <span>
              {reviewedCount} of {extraction.claims_count} claims reviewed
            </span>
          ) : (
            <span>No claims reviewed yet</span>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => router.push(`/reports/${reportId}`)}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmitReview}
            disabled={reviewedCount === 0 || saving}
          >
            {saving ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <CheckCircle className="h-4 w-4 mr-2" />
                Submit Review ({reviewedCount})
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Edit Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Technique Mapping</DialogTitle>
            <DialogDescription>
              Adjust the technique ID or confidence score for this claim
            </DialogDescription>
          </DialogHeader>
          {editingClaim && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="technique-id">Technique ID</Label>
                <Input
                  id="technique-id"
                  value={editedTechniqueId}
                  onChange={(e) => setEditedTechniqueId(e.target.value)}
                  placeholder="e.g., T1055.001"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Current: {editingClaim.claim.external_id}
                </p>
              </div>
              <div>
                <Label htmlFor="confidence">Confidence Score</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="confidence"
                    type="number"
                    min="0"
                    max="100"
                    value={editedConfidence}
                    onChange={(e) => setEditedConfidence(parseInt(e.target.value))}
                  />
                  <span className="text-sm text-muted-foreground">%</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Current: {editingClaim.claim.confidence}%
                </p>
              </div>
              <div>
                <Label>Evidence Preview</Label>
                <ScrollArea className="h-[100px] w-full rounded-md border p-2">
                  <p className="text-sm italic">
                    "{editingClaim.claim.quotes[0]}"
                  </p>
                </ScrollArea>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleEditSave}>
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}