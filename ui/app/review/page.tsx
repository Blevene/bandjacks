"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  ChevronRight,
  Filter,
  Download,
  Archive,
  TrendingUp,
  Loader2,
  Target,
  Search
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

interface QueueStats {
  total_candidates: number;
  by_status: Record<string, number>;
  pending_review: number;
  confidence_stats: {
    average: number;
    min: number;
    max: number;
    count: number;
  };
  recent_7_days: number;
  promotion_rate: number;
  rejection_rate: number;
}

export default function ReviewQueuePage() {
  const [candidates, setCandidates] = useState<CandidatePattern[]>([]);
  const [stats, setStats] = useState<QueueStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCandidates, setSelectedCandidates] = useState<Set<string>>(new Set());
  const [statusFilter, setStatusFilter] = useState<string>("pending");
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [searchQuery, setSearchQuery] = useState("");
  const { toast } = useToast();

  useEffect(() => {
    fetchCandidates();
    fetchStats();
  }, [statusFilter, minConfidence]);

  const fetchCandidates = async () => {
    try {
      const params = new URLSearchParams();
      if (statusFilter && statusFilter !== "all") {
        params.append("status", statusFilter);
      }
      if (minConfidence > 0) {
        params.append("min_confidence", minConfidence.toString());
      }
      params.append("limit", "100");

      const response = await fetch(`http://localhost:8001/v1/review/candidates/?${params}`, {
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (response.ok) {
        const data = await response.json();
        setCandidates(data);
      }
    } catch (error) {
      console.error("Error fetching candidates:", error);
      toast({
        title: "Error loading candidates",
        description: "Failed to load review queue",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch("http://localhost:8001/v1/review/candidates/stats/summary");
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error("Error fetching stats:", error);
    }
  };

  const handleApprove = async (candidateId: string) => {
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
            notes: "Approved via UI",
          }),
        }
      );

      if (response.ok) {
        toast({
          title: "Candidate approved",
          description: "The candidate has been promoted to an attack pattern",
        });
        fetchCandidates();
        fetchStats();
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

  const handleReject = async (candidateId: string) => {
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
            reason: "Not a valid attack pattern",
          }),
        }
      );

      if (response.ok) {
        toast({
          title: "Candidate rejected",
          description: "The candidate has been marked as rejected",
        });
        fetchCandidates();
        fetchStats();
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

  const filteredCandidates = candidates.filter((candidate) => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        candidate.name.toLowerCase().includes(query) ||
        candidate.description.toLowerCase().includes(query)
      );
    }
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Review Queue</h1>
          <p className="text-muted-foreground">
            Review and approve candidate attack patterns from extraction
          </p>
        </div>
        <div className="flex gap-2">
          <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
            <Archive className="h-4 w-4" />
            Archive Old
          </button>
          <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
            <Download className="h-4 w-4" />
            Export
          </button>
        </div>
      </div>

      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Pending Review</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.pending_review}</div>
              <p className="text-xs text-muted-foreground">
                Awaiting analyst decision
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Avg. Confidence</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${getConfidenceColor(stats.confidence_stats.average)}`}>
                {stats.confidence_stats.average.toFixed(0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                Range: {stats.confidence_stats.min}-{stats.confidence_stats.max}%
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Promotion Rate</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">
                {stats.promotion_rate.toFixed(0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                Approved to full patterns
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Rejection Rate</CardTitle>
              <XCircle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-500">
                {stats.rejection_rate.toFixed(0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                False positives filtered
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Recent Activity</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.recent_7_days}</div>
              <p className="text-xs text-muted-foreground">
                New in last 7 days
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Candidate Patterns</CardTitle>
              <CardDescription>
                Review extracted patterns before promoting to knowledge graph
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Status:</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-1 border rounded-md"
                >
                  <option value="all">All</option>
                  <option value="pending">Pending</option>
                  <option value="promoted">Approved</option>
                  <option value="rejected">Rejected</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Min Confidence:</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={minConfidence}
                  onChange={(e) => setMinConfidence(Number(e.target.value))}
                  className="w-20 px-2 py-1 border rounded-md"
                />
              </div>
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search candidates..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="px-3 py-1 border rounded-md"
                />
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredCandidates.length === 0 ? (
              <div className="text-center py-12">
                <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-lg font-medium">No candidates found</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Adjust your filters or wait for new extractions
                </p>
              </div>
            ) : (
              filteredCandidates.map((candidate) => (
                <div
                  key={candidate.id}
                  className="flex items-start gap-4 p-4 border rounded-lg hover:bg-muted/50"
                >
                  <input
                    type="checkbox"
                    checked={selectedCandidates.has(candidate.id)}
                    onChange={(e) => {
                      const newSelected = new Set(selectedCandidates);
                      if (e.target.checked) {
                        newSelected.add(candidate.id);
                      } else {
                        newSelected.delete(candidate.id);
                      }
                      setSelectedCandidates(newSelected);
                    }}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium">{candidate.name}</h3>
                          <Badge className={getStatusColor(candidate.status)} variant="secondary">
                            {candidate.status}
                          </Badge>
                          <span className={`text-sm font-medium ${getConfidenceColor(candidate.confidence)}`}>
                            {candidate.confidence.toFixed(0)}% confidence
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {candidate.description}
                        </p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          <span>Source: {candidate.source_report}</span>
                          {candidate.created_at && (
                            <span>Created: {format(new Date(candidate.created_at), "MMM d, yyyy")}</span>
                          )}
                          {candidate.reviewed_by && (
                            <span>Reviewed by: {candidate.reviewed_by}</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {candidate.status === "pending" && (
                          <>
                            <button
                              onClick={() => handleApprove(candidate.id)}
                              className="p-2 text-green-500 hover:bg-green-500/20 rounded-md"
                              title="Approve"
                            >
                              <CheckCircle className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => handleReject(candidate.id)}
                              className="p-2 text-red-500 hover:bg-red-500/20 rounded-md"
                              title="Reject"
                            >
                              <XCircle className="h-4 w-4" />
                            </button>
                          </>
                        )}
                        <Link href={`/review/${candidate.id}`}>
                          <button className="p-2 hover:bg-muted rounded-md" title="View Details">
                            <ChevronRight className="h-4 w-4" />
                          </button>
                        </Link>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}