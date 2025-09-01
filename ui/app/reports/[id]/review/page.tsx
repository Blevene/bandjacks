"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { 
  Loader2, 
  ChevronLeft, 
  AlertCircle,
} from "lucide-react";
import type { Report, UnifiedReviewDecision } from "@/lib/report-types";
import { isExtractionComplete } from "@/lib/report-types";
import { UnifiedReview } from "@/components/reports/unified-review";

export default function ReportReviewPage() {
  const params = useParams();
  const router = useRouter();
  const reportId = params.id as string;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
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

  const handleSubmitReview = async (decisions: UnifiedReviewDecision[], globalNotes: string) => {
    try {
      const response = await fetch(`http://localhost:8000/v1/reports/${reportId}/unified-review`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          report_id: reportId,
          reviewer_id: 'current-user', // TODO: Get from auth context
          decisions,
          global_notes: globalNotes,
          review_timestamp: new Date().toISOString(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to submit review');
      }

      const result = await response.json();
      
      toast({
        title: "Review submitted successfully",
        description: `${result.items_reviewed} items reviewed (${result.items_approved} approved, ${result.items_rejected} rejected)`,
      });

      setTimeout(() => router.push(`/reports/${reportId}`), 1500);
    } catch (error: any) {
      console.error("Error submitting review:", error);
      toast({
        title: "Error submitting review",
        description: error.message || "Failed to submit review",
        variant: "destructive",
      });
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
            Review Report: {report.name}
          </h1>
          <p className="text-muted-foreground mt-2">
            Review all extracted entities, techniques, and attack flow steps
          </p>
        </div>
      </div>

      {/* Unified Review Component */}
      <UnifiedReview 
        report={report}
        onSubmit={handleSubmitReview}
        readOnly={false}
      />
    </div>
  );
}