"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Loader2,
  AlertTriangle,
  Shield,
  Hash,
  TrendingUp,
  Clock,
  ChevronRight,
  CheckCircle,
  XCircle,
  Edit,
  Eye,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import type { Report } from "@/lib/report-types";
import { getConfidenceColor, getConfidenceBadgeVariant, isExtractionComplete } from "@/lib/report-types";
import { TechniqueClaims } from "@/components/reports/technique-claims";
import { EvidenceViewer } from "@/components/reports/evidence-viewer";
import { FlowVisualization } from "@/components/reports/flow-visualization";
import { EntityReview } from "@/components/reports/entity-review";

export default function ReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const reportId = params.id as string;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"overview" | "claims" | "entities" | "evidence" | "flow">("overview");
  const { toast } = useToast();

  useEffect(() => {
    if (reportId) {
      fetchReport();
    }
  }, [reportId]);

  const fetchReport = async () => {
    try {
      // Use the API directly at port 8000
      const response = await fetch(`http://localhost:8000/v1/reports/${reportId}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch report: ${response.statusText}`);
      }
      const data = await response.json();
      console.log('Fetched report data:', data);
      console.log('Extraction data:', data.extraction);
      console.log('Claims count:', data.extraction?.claims?.length);
      setReport(data);
    } catch (error: any) {
      console.error("Error fetching report:", error);
      toast({
        title: "Error loading report",
        description: error.message || "Failed to load report details",
        variant: "destructive",
      });
      if (error.message?.includes("404")) {
        setTimeout(() => router.push("/reports"), 2000);
      }
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-lg font-medium">Report not found</p>
        <p className="text-sm text-muted-foreground mt-2">
          The requested report could not be found
        </p>
      </div>
    );
  }

  const hasExtraction = isExtractionComplete(report);
  const extraction = report.extraction;
  const hasFlow = extraction?.flow && extraction.flow.steps.length > 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
            <Link href="/reports" className="hover:text-foreground">
              Reports
            </Link>
            <ChevronRight className="h-4 w-4" />
            <span className="text-foreground">{report.name}</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <FileText className="h-8 w-8 text-blue-500" />
            {report.name}
          </h1>
          {report.description && (
            <p className="text-muted-foreground mt-2 max-w-3xl line-clamp-3">
              {report.description}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-2 items-end">
          <Badge variant={
            report.status === 'approved' ? 'default' :
            report.status === 'reviewed' ? 'secondary' :
            report.status === 'rejected' ? 'destructive' :
            'outline'
          }>
            {report.status.replace('_', ' ').toUpperCase()}
          </Badge>
          {hasExtraction && report.status === 'pending_review' && (
            <Button
              onClick={() => router.push(`/reports/${report.report_id}/review`)}
              className="flex items-center gap-2"
            >
              <Edit className="h-4 w-4" />
              Review Claims
            </Button>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      {hasExtraction && extraction && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Techniques</CardTitle>
              <Shield className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{extraction.techniques_count}</div>
              <p className="text-xs text-muted-foreground">
                Unique ATT&CK techniques
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Claims</CardTitle>
              <Hash className="h-4 w-4 text-purple-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{extraction.claims_count}</div>
              <p className="text-xs text-muted-foreground">
                Evidence-backed claims
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Confidence</CardTitle>
              <TrendingUp className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <div className="text-2xl font-bold">
                  {Math.round(extraction.confidence_avg)}%
                </div>
                <Badge variant={getConfidenceBadgeVariant(extraction.confidence_avg)}>
                  {extraction.confidence_avg >= 80 ? 'HIGH' :
                   extraction.confidence_avg >= 50 ? 'MEDIUM' : 'LOW'}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Average confidence score
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Modified</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-sm font-medium">
                {format(new Date(report.modified), "MMM d, yyyy")}
              </div>
              <p className="text-xs text-muted-foreground">
                {format(new Date(report.modified), "HH:mm")}
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Main Content */}
      {hasExtraction && extraction ? (
        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="claims">
              Claims ({extraction.claims_count})
            </TabsTrigger>
            <TabsTrigger value="entities">
              Entities {extraction.entities && `(${extraction.entities.entities?.length || 0})`}
            </TabsTrigger>
            <TabsTrigger value="evidence">Evidence</TabsTrigger>
            <TabsTrigger value="flow" disabled={!hasFlow}>
              Flow {hasFlow && `(${extraction.flow!.steps.length})`}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            {/* Extraction Metrics */}
            {extraction.metrics && Object.keys(extraction.metrics).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Extraction Metrics</CardTitle>
                  <CardDescription>
                    Performance and processing statistics
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(extraction.metrics).map(([key, value]) => (
                      <div key={key}>
                        <p className="text-sm font-medium text-muted-foreground">
                          {key.replace(/_/g, ' ').toUpperCase()}
                        </p>
                        <p className="text-lg font-semibold">{String(value)}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Technique Summary */}
            <Card>
              <CardHeader>
                <CardTitle>Technique Summary</CardTitle>
                <CardDescription>
                  Distribution of extracted techniques by confidence
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {extraction.claims
                    .reduce((acc, claim) => {
                      const existing = acc.find(t => t.external_id === claim.external_id);
                      if (existing) {
                        existing.count++;
                        existing.maxConfidence = Math.max(existing.maxConfidence, claim.confidence);
                      } else {
                        acc.push({
                          external_id: claim.external_id,
                          name: claim.name,
                          count: 1,
                          maxConfidence: claim.confidence
                        });
                      }
                      return acc;
                    }, [] as Array<{external_id: string, name: string, count: number, maxConfidence: number}>)
                    .sort((a, b) => b.maxConfidence - a.maxConfidence)
                    .slice(0, 10)
                    .map(technique => (
                      <div key={technique.external_id} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4 text-blue-500" />
                          <span className="font-medium">{technique.external_id}</span>
                          <span className="text-sm text-muted-foreground">{technique.name}</span>
                          {technique.count > 1 && (
                            <Badge variant="secondary" className="text-xs">
                              ×{technique.count}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-sm font-medium ${getConfidenceColor(technique.maxConfidence)}`}>
                            {technique.maxConfidence}%
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>

            {/* Review Status */}
            {report.review && (
              <Card>
                <CardHeader>
                  <CardTitle>Review Status</CardTitle>
                  <CardDescription>
                    Current review state and decisions
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Status</span>
                      <Badge>{report.review.status}</Badge>
                    </div>
                    {report.review.reviewer_id && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Reviewer</span>
                        <span className="text-sm">{report.review.reviewer_id}</span>
                      </div>
                    )}
                    {report.review.reviewed_at && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Reviewed</span>
                        <span className="text-sm">
                          {format(new Date(report.review.reviewed_at), "MMM d, yyyy HH:mm")}
                        </span>
                      </div>
                    )}
                    {Object.keys(report.review.decisions || {}).length > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Decisions</span>
                        <span className="text-sm">
                          {Object.keys(report.review.decisions).length} techniques reviewed
                        </span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="claims">
            <TechniqueClaims 
              claims={extraction.claims}
              reviewMode={false}
            />
          </TabsContent>

          <TabsContent value="entities">
            <EntityReview
              entities={extraction.entities}
              readOnly={report.status === 'approved'}
              onReviewComplete={async (reviewedEntities) => {
                try {
                  // Submit entity review to API
                  const response = await fetch(`http://localhost:8000/v1/reports/${reportId}/entities/review`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      entities: reviewedEntities,
                      reviewer_id: 'user-1', // TODO: Get from auth context
                      timestamp: new Date().toISOString()
                    })
                  });
                  
                  if (!response.ok) {
                    throw new Error('Failed to submit entity review');
                  }
                  
                  toast({
                    title: "Entity review submitted",
                    description: "Your entity review has been saved successfully.",
                  });
                  
                  // Refresh report to show updated status
                  fetchReport();
                } catch (error: any) {
                  toast({
                    title: "Error submitting review",
                    description: error.message || "Failed to save entity review",
                    variant: "destructive",
                  });
                }
              }}
            />
          </TabsContent>

          <TabsContent value="evidence">
            <EvidenceViewer 
              claims={extraction.claims}
              reportText={report.description || ""}
            />
          </TabsContent>

          <TabsContent value="flow">
            {hasFlow && extraction.flow && (
              <FlowVisualization flow={extraction.flow} />
            )}
          </TabsContent>
        </Tabs>
      ) : (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            No extraction data available for this report. 
            {report.status === 'pending_review' && " The report may still be processing."}
          </AlertDescription>
        </Alert>
      )}

      {/* Footer */}
      <Card className="bg-muted/30">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Report ID: {report.report_id}</span>
            <span>Created: {format(new Date(report.created), "MMM d, yyyy HH:mm")}</span>
            <span>Modified: {format(new Date(report.modified), "MMM d, yyyy HH:mm")}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}