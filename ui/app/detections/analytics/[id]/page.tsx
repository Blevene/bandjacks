"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Code,
  FileText,
  GitBranch,
  Database,
  Send,
  MessageSquare,
  ThumbsUp,
  ThumbsDown,
  ExternalLink,
  Tag,
  Activity
} from "lucide-react";
import Link from "next/link";

export default function AnalyticDetailPage() {
  const params = useParams();
  const analyticId = params.id as string;
  const [analytic, setAnalytic] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [feedbackLoading, setFeedbackLoading] = useState(false);
  const [feedbackText, setFeedbackText] = useState("");
  const [rating, setRating] = useState<"positive" | "negative" | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (analyticId) {
      fetchAnalyticDetails();
    }
  }, [analyticId]);

  const fetchAnalyticDetails = async () => {
    try {
      const result = await typedApi.detections.getAnalytic(analyticId);
      setAnalytic(result);
    } catch (error: any) {
      toast({
        title: "Error loading analytic",
        description: error.response?.data?.detail || "Failed to load analytic details",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const submitFeedback = async () => {
    if (!rating || !feedbackText.trim()) {
      toast({
        title: "Missing feedback",
        description: "Please provide both a rating and feedback text",
        variant: "destructive",
      });
      return;
    }

    setFeedbackLoading(true);
    try {
      await typedApi.feedback.submitAnalytic(analyticId, {
        score: rating === "positive" ? 5 : rating === "negative" ? 1 : 3,
        labels: [],
        overrides: {},
        env_id: "default",
        comment: feedbackText,
        analyst_id: "current_user",
      });
      
      toast({
        title: "Feedback submitted",
        description: "Thank you for your feedback!",
      });
      
      setFeedbackText("");
      setRating(null);
    } catch (error: any) {
      toast({
        title: "Failed to submit feedback",
        description: error.response?.data?.detail || "Failed to submit feedback",
        variant: "destructive",
      });
    } finally {
      setFeedbackLoading(false);
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence?.toLowerCase()) {
      case "high":
        return "bg-green-500/20 text-green-500";
      case "medium":
        return "bg-yellow-500/20 text-yellow-500";
      case "low":
        return "bg-red-500/20 text-red-500";
      default:
        return "bg-gray-500/20 text-gray-500";
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!analytic) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <p className="text-lg font-medium">Analytic not found</p>
          <p className="text-sm text-muted-foreground mt-2">
            The analytic "{analyticId}" could not be found.
          </p>
          <Link href="/detections/strategies">
            <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              Back to Strategies
            </button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-2">
          <h1 className="text-3xl font-bold tracking-tight">
            {analytic.name || analytic.analytic_id}
          </h1>
          {analytic.confidence && (
            <span className={`px-3 py-1 text-sm rounded-md font-medium ${getConfidenceColor(analytic.confidence)}`}>
              {analytic.confidence} confidence
            </span>
          )}
        </div>
        {analytic.description && (
          <p className="text-muted-foreground">{analytic.description}</p>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Platform</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {analytic.platform || "Any"}
            </div>
            <p className="text-xs text-muted-foreground">
              Target platform
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Type</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {analytic.type || "Rule"}
            </div>
            <p className="text-xs text-muted-foreground">
              Detection type
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Data Sources</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {analytic.data_sources?.length || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Required sources
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Version</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {analytic.version || "1.0"}
            </div>
            <p className="text-xs text-muted-foreground">
              Current version
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Detection Logic</CardTitle>
            <CardDescription>Query or rule definition</CardDescription>
          </CardHeader>
          <CardContent>
            {analytic.logic ? (
              <div className="space-y-3">
                <div className="bg-muted p-4 rounded-md">
                  <pre className="text-xs font-mono overflow-x-auto">
                    <code>{JSON.stringify(analytic.logic, null, 2)}</code>
                  </pre>
                </div>
                {analytic.query_language && (
                  <div className="flex items-center gap-2 text-sm">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span>Language: {analytic.query_language}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <Code className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  No detection logic available
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Metadata</CardTitle>
            <CardDescription>Additional information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {analytic.technique_id && (
              <div className="flex items-start gap-2">
                <Tag className="h-4 w-4 text-blue-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">ATT&CK Technique</p>
                  <Link href={`/techniques/${analytic.technique_id}`}>
                    <p className="text-xs text-primary hover:underline">
                      {analytic.technique_id}
                    </p>
                  </Link>
                </div>
              </div>
            )}

            {analytic.data_sources && analytic.data_sources.length > 0 && (
              <div className="flex items-start gap-2">
                <Database className="h-4 w-4 text-green-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Data Sources</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {analytic.data_sources.map((source: string, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-secondary rounded">
                        {source}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {analytic.false_positive_rate && (
              <div className="flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">False Positive Rate</p>
                  <p className="text-xs text-muted-foreground">
                    {analytic.false_positive_rate}
                  </p>
                </div>
              </div>
            )}

            {analytic.sigma_rules && analytic.sigma_rules.length > 0 && (
              <div className="flex items-start gap-2">
                <FileText className="h-4 w-4 text-purple-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Linked Sigma Rules</p>
                  <p className="text-xs text-muted-foreground">
                    {analytic.sigma_rules.length} rules linked
                  </p>
                </div>
              </div>
            )}

            {analytic.last_updated && (
              <div className="flex items-start gap-2">
                <Activity className="h-4 w-4 text-orange-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Last Updated</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(analytic.last_updated).toLocaleDateString()}
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Provide Feedback</CardTitle>
          <CardDescription>
            Help improve this detection by providing feedback
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <button
              onClick={() => setRating("positive")}
              className={`flex-1 px-4 py-3 rounded-md border transition-colors flex items-center justify-center gap-2 ${
                rating === "positive"
                  ? "bg-green-500/20 border-green-500 text-green-500"
                  : "hover:bg-muted"
              }`}
            >
              <ThumbsUp className="h-5 w-5" />
              Helpful
            </button>
            <button
              onClick={() => setRating("negative")}
              className={`flex-1 px-4 py-3 rounded-md border transition-colors flex items-center justify-center gap-2 ${
                rating === "negative"
                  ? "bg-red-500/20 border-red-500 text-red-500"
                  : "hover:bg-muted"
              }`}
            >
              <ThumbsDown className="h-5 w-5" />
              Needs Improvement
            </button>
          </div>

          <textarea
            value={feedbackText}
            onChange={(e) => setFeedbackText(e.target.value)}
            placeholder="Provide detailed feedback about this detection..."
            className="w-full h-32 p-3 text-sm border rounded-md bg-background resize-none"
          />

          <button
            onClick={submitFeedback}
            disabled={!rating || !feedbackText.trim() || feedbackLoading}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {feedbackLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
            Submit Feedback
          </button>
        </CardContent>
      </Card>

      {analytic.references && analytic.references.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>References</CardTitle>
            <CardDescription>External documentation</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytic.references.map((ref: any, idx: number) => (
                <a
                  key={idx}
                  href={ref.url || ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-primary hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  {ref.title || ref.url || ref}
                </a>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}