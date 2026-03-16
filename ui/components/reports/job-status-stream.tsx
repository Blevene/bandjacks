"use client";

import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { API_BASE_URL } from "@/lib/config";
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
  X,
  WifiOff,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface JobStatusStreamProps {
  jobId: string;
  onComplete?: (result: any) => void;
  onError?: (error: any) => void;
  showCancel?: boolean;
  autoRedirect?: boolean;
  useSSE?: boolean; // Flag to use SSE or fall back to polling
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

export function JobStatusStream({
  jobId,
  onComplete,
  onError,
  showCancel = true,
  autoRedirect = true,
  useSSE = true,
}: JobStatusStreamProps) {
  const [job, setJob] = useState<JobStatus | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;
  const { toast } = useToast();

  useEffect(() => {
    if (!useSSE) {
      // If SSE is disabled, import and use the polling component
      // This is a fallback mechanism
      return;
    }

    let intervalId: NodeJS.Timeout | null = null;

    const connectSSE = () => {
      // Construct the SSE URL
      const sseUrl = `${API_BASE_URL}/v1/reports/jobs/${jobId}/stream`;

      // Create EventSource connection
      const eventSource = new EventSource(sseUrl);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        console.log("SSE connection opened");
        setIsConnected(true);
        setConnectionError(null);
        reconnectAttemptsRef.current = 0;
      };

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Check for error in data
          if (data.error) {
            console.error("SSE error:", data.error);
            setConnectionError(data.error);
            eventSource.close();
            return;
          }

          // Update job status
          setJob(data);

          // Update elapsed time if job is running
          if (data.started_at && data.status === "processing") {
            const start = new Date(data.started_at).getTime();
            const now = Date.now();
            setElapsedTime(Math.floor((now - start) / 1000));
          }

          // Handle completion
          if (data.status === "completed") {
            console.log("Job completed:", data);
            setIsConnected(false);
            eventSource.close();

            if (onComplete) {
              onComplete(data.result);
            }

            toast({
              title: "Processing Complete",
              description: `Extracted ${data.result?.techniques_count || 0} techniques`,
            });

            // Auto-redirect if enabled
            if (autoRedirect && data.result?.report_id) {
              setTimeout(() => {
                window.location.href = `/reports/${data.result.report_id}`;
              }, 2000);
            }
          }

          // Handle failure
          if (data.status === "failed") {
            console.error("Job failed:", data.error);
            setIsConnected(false);
            eventSource.close();

            if (onError) {
              onError(data.error);
            }

            toast({
              variant: "destructive",
              title: "Processing Failed",
              description: data.error || "Unknown error occurred",
            });
          }
        } catch (error) {
          console.error("Failed to parse SSE data:", error);
        }
      };

      eventSource.addEventListener("heartbeat", (event) => {
        // Handle heartbeat events
        try {
          const data = JSON.parse(event.data);
          setJob(data);
        } catch (error) {
          console.error("Failed to parse heartbeat:", error);
        }
      });

      eventSource.onerror = (error) => {
        console.error("SSE connection error:", error);
        setIsConnected(false);
        eventSource.close();

        // Attempt to reconnect with exponential backoff
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);

          setConnectionError(`Connection lost. Reconnecting in ${delay / 1000}s...`);

          setTimeout(() => {
            console.log(`Reconnecting (attempt ${reconnectAttemptsRef.current})...`);
            connectSSE();
          }, delay);
        } else {
          setConnectionError("Connection lost. Please refresh the page.");

          toast({
            variant: "destructive",
            title: "Connection Lost",
            description: "Unable to maintain connection to the server. Please refresh the page.",
          });
        }
      };
    };

    // Start SSE connection
    connectSSE();

    // Update elapsed time every second
    intervalId = setInterval(() => {
      if (job?.started_at && job?.status === "processing") {
        const start = new Date(job.started_at).getTime();
        const now = Date.now();
        setElapsedTime(Math.floor((now - start) / 1000));
      }
    }, 1000);

    // Cleanup on unmount
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [jobId, useSSE, onComplete, onError, toast, autoRedirect]);

  const handleCancel = async () => {
    // Note: Backend doesn't support cancellation yet
    toast({
      title: "Cancellation Requested",
      description: "Job cancellation is not yet supported",
    });
  };

  const handleRetry = () => {
    // Reset connection error and try to reconnect
    setConnectionError(null);
    reconnectAttemptsRef.current = 0;

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    // Trigger re-connection by updating a dependency
    window.location.reload();
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
            <span>Connecting to job stream...</span>
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
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <span>Job ID: {jobId}</span>
                {isConnected && (
                  <Badge variant="outline">
                    <span className="mr-1 h-2 w-2 bg-green-500 rounded-full inline-block animate-pulse" />
                    Live
                  </Badge>
                )}
              </div>
            </div>
          </div>
          <Badge variant={getStatusColor() as any}>
            {job.status.toUpperCase()}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Connection Error Alert */}
        {connectionError && (
          <Alert variant="destructive">
            <WifiOff className="h-4 w-4" />
            <AlertDescription className="flex items-center justify-between">
              <span>{connectionError}</span>
              <Button variant="outline" size="sm" onClick={handleRetry}>
                <RefreshCw className="h-4 w-4 mr-1" />
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        )}

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
              Retry Connection
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