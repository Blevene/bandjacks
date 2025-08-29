"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { 
  GitBranch,
  Loader2,
  ArrowRight,
  CheckCircle,
  AlertTriangle,
  Activity,
  TrendingUp,
  FileText,
  RefreshCw
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";

interface ValidatedTransition {
  from_technique: string;
  from_name?: string;
  to_technique: string;
  to_name?: string;
  confidence: number;
  verdict: string;
  features?: Record<string, any>;
}

interface SequenceAnalysis {
  intrusion_set_id: string;
  intrusion_set_name: string;
  intrusion_set_description?: string;
  model_id?: string;
  created_at?: string;
  parameters?: Record<string, any>;
  statistics?: Record<string, any>;
  validated_transitions: ValidatedTransition[];
  techniques_count: number;
  transitions_count: number;
}

export default function SequenceAnalysisPage() {
  const params = useParams();
  const id = params.id as string;
  
  const [analysis, setAnalysis] = useState<SequenceAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [reanalyzing, setReanalyzing] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (id) {
      fetchAnalysis();
    }
  }, [id]);

  const fetchAnalysis = async () => {
    try {
      const response = await fetch(
        `http://localhost:8000/v1/sequence/analysis/${id}`
      );

      if (response.ok) {
        const data = await response.json();
        setAnalysis(data);
      } else if (response.status === 404) {
        // No analysis exists yet
        setAnalysis(null);
      } else {
        const error = await response.json();
        toast({
          title: "Error loading analysis",
          description: error.detail || "Failed to load sequence analysis",
          variant: "destructive",
        });
      }
    } catch (error: any) {
      console.error("Error fetching analysis:", error);
      toast({
        title: "Error loading analysis",
        description: "Failed to load sequence analysis",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async () => {
    setReanalyzing(true);
    
    try {
      const response = await fetch(
        `http://localhost:8000/v1/sequence/analyze/${id}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          }
        }
      );

      if (response.ok) {
        const result = await response.json();
        
        toast({
          title: "Analysis complete",
          description: `Found ${result.validation_results?.validated_transitions?.length || 0} validated transitions`,
        });
        
        // Refresh the analysis
        fetchAnalysis();
      } else {
        const error = await response.json();
        toast({
          title: "Analysis failed",
          description: error.detail || "Failed to analyze sequences",
          variant: "destructive",
        });
      }
    } catch (error: any) {
      console.error("Error analyzing sequences:", error);
      toast({
        title: "Analysis error",
        description: "Failed to analyze intrusion set sequences",
        variant: "destructive",
      });
    } finally {
      setReanalyzing(false);
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return "text-green-500";
    if (confidence >= 0.5) return "text-yellow-500";
    return "text-red-500";
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case "forward":
      case "i->j":
        return <ArrowRight className="h-4 w-4 text-blue-500" />;
      case "reverse":
      case "j->i":
        return <ArrowRight className="h-4 w-4 text-blue-500 rotate-180" />;
      case "bidirectional":
        return <Activity className="h-4 w-4 text-purple-500" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Sequence Analysis</h1>
            <p className="text-muted-foreground">
              No analysis found for this intrusion set
            </p>
          </div>
        </div>

        <Card>
          <CardContent className="py-12 text-center">
            <GitBranch className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium">No analysis available</p>
            <p className="text-sm text-muted-foreground mt-2">
              Run sequence analysis to generate validated transitions
            </p>
            <button
              onClick={runAnalysis}
              disabled={reanalyzing}
              className="mt-4 flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 mx-auto"
            >
              {reanalyzing ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              Run Analysis
            </button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{analysis.intrusion_set_name}</h1>
          <p className="text-muted-foreground">
            {analysis.intrusion_set_description || "Sequence analysis and validated transitions"}
          </p>
        </div>
        <div className="flex gap-2">
          <Link href={`/sequences/${id}/report`}>
            <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
              <FileText className="h-4 w-4" />
              View Report
            </button>
          </Link>
          <button
            onClick={runAnalysis}
            disabled={reanalyzing}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {reanalyzing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Re-analyze
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Techniques</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analysis.techniques_count}</div>
            <p className="text-xs text-muted-foreground">
              Unique techniques
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Transitions</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analysis.transitions_count}</div>
            <p className="text-xs text-muted-foreground">
              Total transitions
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Validated</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analysis.validated_transitions.length}</div>
            <p className="text-xs text-muted-foreground">
              High confidence
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Model</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm font-medium truncate">
              {analysis.model_id ? analysis.model_id.slice(0, 12) : "N/A"}
            </div>
            {analysis.created_at && (
              <p className="text-xs text-muted-foreground">
                {format(new Date(analysis.created_at), "MMM d, HH:mm")}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Validated Transitions</CardTitle>
          <CardDescription>
            High-confidence technique sequences validated by the judge model
          </CardDescription>
        </CardHeader>
        <CardContent>
          {analysis.validated_transitions.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No validated transitions found. Run analysis with judge enabled.
            </p>
          ) : (
            <div className="space-y-3">
              {analysis.validated_transitions.map((transition, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50"
                >
                  <div className="flex items-center gap-4 flex-1">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">
                          {transition.from_name || transition.from_technique}
                        </span>
                        {getVerdictIcon(transition.verdict)}
                        <span className="font-medium text-sm">
                          {transition.to_name || transition.to_technique}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 mt-1">
                        <span className="text-xs text-muted-foreground">
                          {transition.from_technique} → {transition.to_technique}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${getConfidenceColor(transition.confidence)}`}>
                        {(transition.confidence * 100).toFixed(0)}%
                      </span>
                      <Badge variant="secondary" className="text-xs">
                        {transition.verdict}
                      </Badge>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {analysis.parameters && (
        <Card>
          <CardHeader>
            <CardTitle>Model Parameters</CardTitle>
            <CardDescription>
              PTG model configuration used for analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              {Object.entries(analysis.parameters).map(([key, value]) => (
                <div key={key}>
                  <span className="text-sm text-muted-foreground">{key}:</span>
                  <span className="text-sm font-medium ml-2">
                    {typeof value === "boolean" ? (value ? "Yes" : "No") : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}