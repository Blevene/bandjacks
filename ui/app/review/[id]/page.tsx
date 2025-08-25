"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  CheckCircle,
  XCircle,
  ArrowLeft,
  FileJson,
  Target,
  AlertTriangle,
  Info,
  Link as LinkIcon,
  Loader2,
  Clock,
  User,
  Hash,
  FileText
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";

interface CandidatePattern {
  id: string;
  name: string;
  description: string;
  source_text: string;
  source_report: string;
  confidence: number;
  status: string;
  created_at?: string;
  reviewed_by?: string;
  has_embedding: boolean;
}

interface SimilarPattern {
  id: string;
  name: string;
  description: string;
  external_id?: string;
  similarity_score: number;
}

export default function CandidateDetailPage() {
  const params = useParams();
  const router = useRouter();
  const candidateId = params.id as string;
  const [candidate, setCandidate] = useState<CandidatePattern | null>(null);
  const [similarPatterns, setSimilarPatterns] = useState<SimilarPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [approveNotes, setApproveNotes] = useState("");
  const [rejectReason, setRejectReason] = useState("");
  const [showApproveDialog, setShowApproveDialog] = useState(false);
  const [showRejectDialog, setShowRejectDialog] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (candidateId) {
      fetchCandidate();
      fetchSimilarPatterns();
    }
  }, [candidateId]);

  const fetchCandidate = async () => {
    try {
      const response = await fetch(`http://localhost:8001/v1/review/candidates/${candidateId}`);
      if (response.ok) {
        const data = await response.json();
        setCandidate(data);
      } else {
        toast({
          title: "Error",
          description: "Failed to load candidate details",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error("Error fetching candidate:", error);
      toast({
        title: "Error",
        description: "Failed to load candidate details",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchSimilarPatterns = async () => {
    try {
      const response = await fetch(
        `http://localhost:8001/v1/review/candidates/${candidateId}/similar?threshold=0.5`
      );
      if (response.ok) {
        const data = await response.json();
        setSimilarPatterns(data);
      }
    } catch (error) {
      console.error("Error fetching similar patterns:", error);
    }
  };

  const handleApprove = async () => {
    try {
      const response = await fetch(
        `http://localhost:8001/v1/review/candidates/${candidateId}/approve`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            reviewer_id: "analyst-1", // TODO: Get from auth context
            notes: approveNotes,
          }),
        }
      );

      if (response.ok) {
        toast({
          title: "Candidate approved",
          description: "The candidate has been promoted to an attack pattern",
        });
        router.push("/review");
      } else {
        throw new Error("Failed to approve");
      }
    } catch (error) {
      console.error("Error approving candidate:", error);
      toast({
        title: "Error",
        description: "Failed to approve candidate",
        variant: "destructive",
      });
    }
  };

  const handleReject = async () => {
    try {
      const response = await fetch(
        `http://localhost:8001/v1/review/candidates/${candidateId}/reject`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            reviewer_id: "analyst-1", // TODO: Get from auth context
            reason: rejectReason,
          }),
        }
      );

      if (response.ok) {
        toast({
          title: "Candidate rejected",
          description: "The candidate has been marked as rejected",
        });
        router.push("/review");
      } else {
        throw new Error("Failed to reject");
      }
    } catch (error) {
      console.error("Error rejecting candidate:", error);
      toast({
        title: "Error",
        description: "Failed to reject candidate",
        variant: "destructive",
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "approved":
      case "promoted":
        return "bg-green-500/20 text-green-500";
      case "rejected":
        return "bg-red-500/20 text-red-500";
      case "pending":
        return "bg-yellow-500/20 text-yellow-500";
      default:
        return "bg-gray-500/20 text-gray-500";
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return "text-green-500";
    if (confidence >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  const getSimilarityColor = (score: number) => {
    if (score >= 0.8) return "text-red-500";
    if (score >= 0.6) return "text-yellow-500";
    return "text-green-500";
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!candidate) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <p className="text-lg font-medium">Candidate not found</p>
          <p className="text-sm text-muted-foreground mt-2">
            The candidate pattern could not be found.
          </p>
          <Link href="/review">
            <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              Back to Review Queue
            </button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/review">
            <button className="p-2 hover:bg-muted rounded-md">
              <ArrowLeft className="h-5 w-5" />
            </button>
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold">{candidate.name}</h1>
              <Badge className={getStatusColor(candidate.status)} variant="secondary">
                {candidate.status}
              </Badge>
            </div>
            <p className="text-muted-foreground">Candidate Pattern Review</p>
          </div>
        </div>
        {candidate.status === "pending" && (
          <div className="flex gap-2">
            <button
              onClick={() => setShowApproveDialog(true)}
              className="flex items-center gap-2 px-4 py-2 bg-green-500 text-white rounded-md hover:bg-green-600"
            >
              <CheckCircle className="h-4 w-4" />
              Approve
            </button>
            <button
              onClick={() => setShowRejectDialog(true)}
              className="flex items-center gap-2 px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600"
            >
              <XCircle className="h-4 w-4" />
              Reject
            </button>
          </div>
        )}
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <div className="md:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Pattern Details</CardTitle>
              <CardDescription>Extracted attack pattern information</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Name</label>
                <p className="text-lg font-medium">{candidate.name}</p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Description</label>
                <p className="mt-1">{candidate.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <Target className="h-3 w-3" />
                    Confidence Score
                  </label>
                  <p className={`text-lg font-medium ${getConfidenceColor(candidate.confidence)}`}>
                    {candidate.confidence.toFixed(1)}%
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <Hash className="h-3 w-3" />
                    Candidate ID
                  </label>
                  <p className="font-mono text-sm">{candidate.id}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Source Context</CardTitle>
              <CardDescription>Original text that led to extraction</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <FileText className="h-3 w-3" />
                    Source Report
                  </label>
                  <p className="mt-1 font-medium">{candidate.source_report}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Extracted From</label>
                  <div className="mt-2 p-4 bg-muted rounded-md">
                    <p className="text-sm italic">{candidate.source_text}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Metadata</CardTitle>
              <CardDescription>Additional information about this candidate</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    Created At
                  </label>
                  <p className="text-sm">
                    {candidate.created_at
                      ? format(new Date(candidate.created_at), "MMM d, yyyy 'at' h:mm a")
                      : "Unknown"}
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <User className="h-3 w-3" />
                    Reviewed By
                  </label>
                  <p className="text-sm">{candidate.reviewed_by || "Not yet reviewed"}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <FileJson className="h-3 w-3" />
                    Has Embedding
                  </label>
                  <p className="text-sm">{candidate.has_embedding ? "Yes" : "No"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Similar Existing Patterns</CardTitle>
              <CardDescription>
                Potentially related techniques in the knowledge graph
              </CardDescription>
            </CardHeader>
            <CardContent>
              {similarPatterns.length === 0 ? (
                <div className="text-center py-4">
                  <Info className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">
                    No similar patterns found
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    This may be a novel technique
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {similarPatterns.map((pattern) => (
                    <div
                      key={pattern.id}
                      className="p-3 border rounded-md hover:bg-muted/50"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className="font-medium text-sm">{pattern.name}</p>
                          {pattern.external_id && (
                            <p className="text-xs text-muted-foreground mt-1">
                              {pattern.external_id}
                            </p>
                          )}
                        </div>
                        <span
                          className={`text-sm font-medium ${getSimilarityColor(
                            pattern.similarity_score
                          )}`}
                        >
                          {(pattern.similarity_score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">
                        {pattern.description}
                      </p>
                      <Link href={`/techniques/${pattern.id}`}>
                        <button className="flex items-center gap-1 mt-2 text-xs text-blue-500 hover:text-blue-600">
                          <LinkIcon className="h-3 w-3" />
                          View technique
                        </button>
                      </Link>
                    </div>
                  ))}
                </div>
              )}
              {similarPatterns.length > 0 && (
                <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-md">
                  <div className="flex gap-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-500 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-yellow-900 dark:text-yellow-100">
                        Review Recommendation
                      </p>
                      <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1">
                        {similarPatterns[0].similarity_score >= 0.8
                          ? "High similarity detected. Consider if this is a duplicate."
                          : similarPatterns[0].similarity_score >= 0.6
                          ? "Moderate similarity. Review if this is a variant or sub-technique."
                          : "Low similarity. This appears to be a distinct technique."}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Approve Dialog */}
      {showApproveDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle>Approve Candidate</CardTitle>
              <CardDescription>
                Promote this candidate to a full attack pattern
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium">Approval Notes (optional)</label>
                <textarea
                  value={approveNotes}
                  onChange={(e) => setApproveNotes(e.target.value)}
                  className="w-full mt-1 p-2 border rounded-md"
                  rows={3}
                  placeholder="Add any notes about this approval..."
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleApprove}
                  className="flex-1 px-4 py-2 bg-green-500 text-white rounded-md hover:bg-green-600"
                >
                  Confirm Approval
                </button>
                <button
                  onClick={() => setShowApproveDialog(false)}
                  className="flex-1 px-4 py-2 border rounded-md hover:bg-muted"
                >
                  Cancel
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Reject Dialog */}
      {showRejectDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle>Reject Candidate</CardTitle>
              <CardDescription>
                Mark this candidate as rejected with a reason
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium">Rejection Reason (required)</label>
                <textarea
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  className="w-full mt-1 p-2 border rounded-md"
                  rows={3}
                  placeholder="Explain why this candidate is being rejected..."
                  required
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleReject}
                  disabled={!rejectReason}
                  className="flex-1 px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Confirm Rejection
                </button>
                <button
                  onClick={() => setShowRejectDialog(false)}
                  className="flex-1 px-4 py-2 border rounded-md hover:bg-muted"
                >
                  Cancel
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}