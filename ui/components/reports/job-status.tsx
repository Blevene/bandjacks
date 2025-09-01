"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  FileSearch,
  Target,
  GitBranch,
  AlertCircle,
  RefreshCw,
  Download,
  X,
} from "lucide-react";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

interface JobStatusProps {
  jobId: string;
  onComplete?: (result: any) => void;
  onError?: (error: any) => void;
  showCancel?: boolean;
  autoRedirect?: boolean;
}

interface JobStatus {
  job_id: string;
  status: "pending" | "processing" | "completed" | "failed";
  progress: number;
  message: string;
  started_at?: string;
  completed_at?: string;
  result?: {
    report_id: string;
    techniques_count: number;
    claims_count: number;
    flow_generated: boolean;
    bundle_size: number;
    extraction_metrics?: {
      total_chunks?: number;
      total_time_sec?: number;
      techniques_found?: number;
    };
  };
  error?: string;
}

const STAGE_ICONS: Record<string, React.ReactElement> = {
  "Extracting techniques": <FileSearch className="h-4 w-4" />,
  "Evaluating campaign": <Target className="h-4 w-4" />,
  "Creating STIX bundle": <GitBranch className="h-4 w-4" />,
  "Upserting to graph": <CheckCircle className="h-4 w-4" />,
};

export function JobStatus({
  jobId,
  onComplete,
  onError,
  showCancel = true,
  autoRedirect = true,
}: JobStatusProps) {
  const [job, setJob] = useState<JobStatus | null>(null);
  const [polling, setPolling] = useState(true);
  const [pollInterval, setPollInterval] = useState(2000); // Start with 2 seconds
  const [elapsedTime, setElapsedTime] = useState(0);
  const [timeoutCount, setTimeoutCount] = useState(0);
  const { toast } = useToast();

  useEffect(() => {
    if (!polling) return;

    const pollJob = async () => {
      try {
        const status = await typedApi.reports.getJobStatus(jobId);
        setJob(status);
        
        // Reset timeout count on successful response
        setTimeoutCount(0);

        // Update elapsed time
        if (status.started_at) {
          const start = new Date(status.started_at).getTime();
          const now = Date.now();
          setElapsedTime(Math.floor((now - start) / 1000));
        }

        // Check completion
        if (status.status === "completed") {
          setPolling(false);
          if (onComplete) {
            onComplete(status.result);
          }
          
          toast({
            title: "Processing Complete",
            description: `Extracted ${status.result?.techniques_count || 0} techniques`,
          });

          // Auto-redirect to report if enabled
          if (autoRedirect && status.result?.report_id) {
            setTimeout(() => {
              window.location.href = `/reports/${status.result.report_id}`;
            }, 2000);
          }
        } else if (status.status === "failed") {
          setPolling(false);
          if (onError) {
            onError(status.error);
          }
          
          toast({
            variant: "destructive",
            title: "Processing Failed",
            description: status.error || "Unknown error occurred",
          });
        }

        // Adjust polling interval based on elapsed time
        if (elapsedTime > 30) {
          setPollInterval(5000); // 5 seconds after 30 seconds
        } else if (elapsedTime > 60) {
          setPollInterval(10000); // 10 seconds after 1 minute
        }
      } catch (error: any) {
        console.error("Failed to poll job status:", error);
        
        // Handle timeout errors specifically
        if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
          setTimeoutCount(prev => prev + 1);
          
          // Stop polling after 5 consecutive timeouts
          if (timeoutCount >= 5) {
            setPolling(false);
            toast({
              variant: "destructive",
              title: "Connection Lost",
              description: "Unable to reach the server. Please check your connection and refresh the page.",
            });
          }
          // Otherwise continue polling - the job is likely still running
          return;
        }
        
        // Don't stop polling on transient errors
        if (error.response?.status === 404) {
          setPolling(false);
          toast({
            variant: "destructive",
            title: "Job Not Found",
            description: "The processing job could not be found",
          });
        }
      }
    };

    const interval = setInterval(pollJob, pollInterval);
    
    // Poll immediately on mount
    pollJob();

    return () => clearInterval(interval);
  }, [jobId, polling, pollInterval, elapsedTime, timeoutCount, onComplete, onError, toast, autoRedirect]);

  const handleCancel = async () => {
    try {
      // Note: Backend doesn't support cancellation yet
      // This would need to be implemented
      toast({
        title: "Cancellation Requested",
        description: "Job cancellation is not yet supported",
      });
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Failed to Cancel",
        description: "Could not cancel the job",
      });
    }
  };

  const handleRetry = () => {
    setPolling(true);
    setPollInterval(2000);
    setElapsedTime(0);
  };

  const getStatusIcon = () => {
    if (!job) return <Loader2 className="h-5 w-5 animate-spin" />;
    
    switch (job.status) {
      case "pending":
        return <Clock className="h-5 w-5 text-yellow-500" />;
      case "processing":
        return <Loader2 className="h-5 w-5 animate-spin text-blue-500" />;
      case "completed":
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case "failed":
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <AlertCircle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = () => {
    if (!job) return "default";
    
    switch (job.status) {
      case "pending":
        return "secondary";
      case "processing":
        return "default";
      case "completed":
        return "success";
      case "failed":
        return "destructive";
      default:
        return "outline";
    }
  };

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
  };

  if (!job) {
    return (
      <Card>
        <CardContent className="py-8">
          <div className="flex items-center justify-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            <span>Loading job status...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <CardTitle>Processing Report</CardTitle>
              <CardDescription>Job ID: {jobId}</CardDescription>
            </div>
          </div>
          <Badge variant={getStatusColor() as any}>
            {job.status.toUpperCase()}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2">
              {STAGE_ICONS[job.message] || <Loader2 className="h-4 w-4 animate-spin" />}
              {job.message}
            </span>
            <span className="text-muted-foreground">{job.progress}%</span>
          </div>
          <Progress value={job.progress} className="h-2" />
        </div>

        {/* Time Elapsed */}
        {job.started_at && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>Elapsed Time</span>
            <span>{formatTime(elapsedTime)}</span>
          </div>
        )}

        {/* Extraction Metrics (if available during processing) */}
        {job.result?.extraction_metrics && (
          <div className="grid grid-cols-3 gap-2 text-center">
            {job.result.extraction_metrics.total_chunks && (
              <div className="space-y-1">
                <p className="text-2xl font-bold">{job.result.extraction_metrics.total_chunks}</p>
                <p className="text-xs text-muted-foreground">Chunks</p>
              </div>
            )}
            {job.result.extraction_metrics.techniques_found !== undefined && (
              <div className="space-y-1">
                <p className="text-2xl font-bold">{job.result.extraction_metrics.techniques_found}</p>
                <p className="text-xs text-muted-foreground">Techniques</p>
              </div>
            )}
            {job.result.extraction_metrics.total_time_sec && (
              <div className="space-y-1">
                <p className="text-2xl font-bold">{formatTime(Math.round(job.result.extraction_metrics.total_time_sec))}</p>
                <p className="text-xs text-muted-foreground">Processing</p>
              </div>
            )}
          </div>
        )}

        {/* Success Result */}
        {job.status === "completed" && job.result && (
          <Alert className="border-green-500/50">
            <CheckCircle className="h-4 w-4 text-green-500" />
            <AlertDescription>
              <div className="space-y-2">
                <p className="font-medium">Report processed successfully!</p>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>Techniques: {job.result.techniques_count}</div>
                  <div>Claims: {job.result.claims_count}</div>
                  <div>Bundle Size: {job.result.bundle_size} objects</div>
                  <div>Flow: {job.result.flow_generated ? "Generated" : "Not generated"}</div>
                </div>
                {autoRedirect && (
                  <p className="text-xs text-muted-foreground">Redirecting to report...</p>
                )}
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Error Result */}
        {job.status === "failed" && job.error && (
          <Alert variant="destructive">
            <XCircle className="h-4 w-4" />
            <AlertDescription>
              <div className="space-y-2">
                <p className="font-medium">Processing failed</p>
                <p className="text-sm">{job.error}</p>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2">
          {job.status === "processing" && showCancel && (
            <Button variant="outline" size="sm" onClick={handleCancel}>
              <X className="h-4 w-4 mr-1" />
              Cancel
            </Button>
          )}
          
          {job.status === "failed" && (
            <Button variant="outline" size="sm" onClick={handleRetry}>
              <RefreshCw className="h-4 w-4 mr-1" />
              Retry
            </Button>
          )}
          
          {job.status === "completed" && job.result && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = `/reports/${job.result?.report_id}`}
            >
              View Report
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}