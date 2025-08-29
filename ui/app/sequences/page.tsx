"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { 
  GitBranch,
  Loader2,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Activity,
  TrendingUp,
  Eye,
  PlayCircle,
  FileText,
  Users,
  Target,
  Filter
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";

interface SequenceSource {
  stix_id: string;
  name: string;
  description?: string;
  source_type: "intrusion-set" | "report" | "campaign";
  techniques_count: number;
  episodes_count?: number;
  flows_count?: number;
  model_id?: string;
  last_analyzed?: string;
  created?: string;
  first_seen?: string;
  last_seen?: string;
  validated_count?: number;
  uncertain_count?: number;
  confidence_level?: string;
}

export default function SequencesPage() {
  const [sources, setSources] = useState<SequenceSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<"all" | "intrusion-set" | "report" | "campaign">("all");
  const { toast } = useToast();

  useEffect(() => {
    fetchSequences();
  }, []);

  const fetchSequences = async () => {
    try {
      // Fetch all sequence sources (intrusion sets, reports, campaigns)
      const response = await fetch("http://localhost:8000/v1/sequence/sources");
      
      if (response.ok) {
        const data = await response.json();
        
        // Process and add confidence levels
        const processedSources = data.sources?.map((source: SequenceSource) => ({
          ...source,
          confidence_level: 
            source.source_type === "intrusion-set" ? (
              source.validated_count && source.validated_count > 5 ? "high" :
              source.validated_count && source.validated_count > 0 ? "medium" : 
              source.model_id ? "low" : undefined
            ) : undefined
        })) || [];
        
        setSources(processedSources);
      }
    } catch (error: any) {
      console.error("Error fetching sequences:", error);
      toast({
        title: "Error loading sequences",
        description: "Failed to load sequence sources",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const analyzeSequence = async (source: SequenceSource) => {
    if (source.source_type !== "intrusion-set") {
      toast({
        title: "Not supported yet",
        description: "Analysis is currently only available for intrusion sets",
      });
      return;
    }

    setAnalyzing(source.stix_id);
    
    try {
      const response = await fetch(
        `http://localhost:8000/v1/sequence/analyze/${source.stix_id}`,
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
        
        // Refresh the list
        fetchSequences();
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
        description: "Failed to analyze sequences",
        variant: "destructive",
      });
    } finally {
      setAnalyzing(null);
    }
  };

  const getSourceIcon = (sourceType: string) => {
    switch (sourceType) {
      case "intrusion-set":
        return <Users className="h-5 w-5 text-blue-500" />;
      case "report":
        return <FileText className="h-5 w-5 text-green-500" />;
      case "campaign":
        return <Target className="h-5 w-5 text-purple-500" />;
      default:
        return <GitBranch className="h-5 w-5 text-gray-500" />;
    }
  };

  const getSourceBadgeColor = (sourceType: string) => {
    switch (sourceType) {
      case "intrusion-set":
        return "bg-blue-500/20 text-blue-500";
      case "report":
        return "bg-green-500/20 text-green-500";
      case "campaign":
        return "bg-purple-500/20 text-purple-500";
      default:
        return "bg-gray-500/20 text-gray-500";
    }
  };

  const getConfidenceColor = (level?: string) => {
    switch (level) {
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

  const getConfidenceIcon = (level?: string) => {
    switch (level) {
      case "high":
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "medium":
        return <Activity className="h-4 w-4 text-yellow-500" />;
      case "low":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const filteredSources = sourceFilter === "all" 
    ? sources 
    : sources.filter(s => s.source_type === sourceFilter);

  const sourceCounts = {
    "intrusion-set": sources.filter(s => s.source_type === "intrusion-set").length,
    "report": sources.filter(s => s.source_type === "report").length,
    "campaign": sources.filter(s => s.source_type === "campaign").length,
  };

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
          <h1 className="text-3xl font-bold tracking-tight">Attack Sequences</h1>
          <p className="text-muted-foreground">
            Analyze attack sequences from threat actors, reports, and campaigns
          </p>
        </div>
        <div className="flex gap-2">
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as any)}
            className="px-3 py-2 border rounded-md bg-background"
          >
            <option value="all">All Sources ({sources.length})</option>
            <option value="intrusion-set">Intrusion Sets ({sourceCounts["intrusion-set"]})</option>
            <option value="report">Reports ({sourceCounts["report"]})</option>
            <option value="campaign">Campaigns ({sourceCounts["campaign"]})</option>
          </select>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Sources</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{sources.length}</div>
            <p className="text-xs text-muted-foreground">
              All sequence sources
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Intrusion Sets</CardTitle>
            <Users className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sourceCounts["intrusion-set"]}
            </div>
            <p className="text-xs text-muted-foreground">
              Threat actors
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Reports</CardTitle>
            <FileText className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sourceCounts["report"]}
            </div>
            <p className="text-xs text-muted-foreground">
              With attack flows
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Campaigns</CardTitle>
            <Target className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sourceCounts["campaign"]}
            </div>
            <p className="text-xs text-muted-foreground">
              With episodes
            </p>
          </CardContent>
        </Card>
      </div>

      {filteredSources.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <GitBranch className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium">No sequence sources found</p>
            <p className="text-sm text-muted-foreground mt-2">
              {sourceFilter !== "all" 
                ? `No ${sourceFilter.replace("-", " ")}s with sequences found`
                : "Load ATT&CK data or ingest reports to analyze sequences"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">
            {sourceFilter === "all" ? "All Sequence Sources" : 
             sourceFilter === "intrusion-set" ? "Intrusion Sets" :
             sourceFilter === "report" ? "Reports with Flows" :
             "Campaigns with Episodes"}
          </h2>
          <div className="grid gap-4">
            {filteredSources.map((source) => (
              <Card key={source.stix_id} className="hover:bg-muted/50 transition-colors">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        {getSourceIcon(source.source_type)}
                        <CardTitle className="text-lg">{source.name}</CardTitle>
                        <Badge className={getSourceBadgeColor(source.source_type)} variant="secondary">
                          {source.source_type.replace("-", " ")}
                        </Badge>
                        {source.confidence_level && getConfidenceIcon(source.confidence_level)}
                        {source.confidence_level && (
                          <Badge className={getConfidenceColor(source.confidence_level)} variant="secondary">
                            {source.confidence_level}
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="mt-2 line-clamp-2">
                        {source.description || `${source.techniques_count} techniques`}
                      </CardDescription>
                    </div>
                    <div className="flex gap-2">
                      {source.source_type === "intrusion-set" ? (
                        source.model_id ? (
                          <>
                            <Link href={`/sequences/${encodeURIComponent(source.stix_id)}`}>
                              <button className="flex items-center gap-2 px-3 py-1 border rounded-md hover:bg-muted">
                                <Eye className="h-4 w-4" />
                                View
                              </button>
                            </Link>
                            <Link href={`/sequences/${encodeURIComponent(source.stix_id)}/report`}>
                              <button className="flex items-center gap-2 px-3 py-1 border rounded-md hover:bg-muted">
                                <FileText className="h-4 w-4" />
                                Report
                              </button>
                            </Link>
                          </>
                        ) : (
                          <button
                            onClick={() => analyzeSequence(source)}
                            disabled={analyzing === source.stix_id}
                            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                          >
                            {analyzing === source.stix_id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <PlayCircle className="h-4 w-4" />
                            )}
                            Analyze
                          </button>
                        )
                      ) : (
                        <Link href={`/sequences/${source.source_type}/${encodeURIComponent(source.stix_id)}`}>
                          <button className="flex items-center gap-2 px-3 py-1 border rounded-md hover:bg-muted">
                            <Eye className="h-4 w-4" />
                            View Sequences
                          </button>
                        </Link>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-6 text-sm text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Activity className="h-4 w-4" />
                      {source.techniques_count} techniques
                    </span>
                    {source.episodes_count !== undefined && source.episodes_count > 0 && (
                      <span className="flex items-center gap-1">
                        <GitBranch className="h-4 w-4" />
                        {source.episodes_count} episodes
                      </span>
                    )}
                    {source.flows_count !== undefined && source.flows_count > 0 && (
                      <span className="flex items-center gap-1">
                        <TrendingUp className="h-4 w-4" />
                        {source.flows_count} flows
                      </span>
                    )}
                    {source.source_type === "intrusion-set" && source.validated_count !== undefined && (
                      <span className="flex items-center gap-1">
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        {source.validated_count} validated
                      </span>
                    )}
                    {source.last_analyzed && (
                      <span className="flex items-center gap-1">
                        Analyzed {format(new Date(source.last_analyzed), "MMM d, yyyy")}
                      </span>
                    )}
                    {source.created && (
                      <span className="flex items-center gap-1">
                        Created {format(new Date(source.created), "MMM d, yyyy")}
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}