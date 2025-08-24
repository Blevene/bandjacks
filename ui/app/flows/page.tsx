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
  Clock,
  Activity,
  Layers,
  FileJson,
  Plus,
  Play,
  Eye
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";

interface AttackFlow {
  flow_id: string;
  name: string;
  description?: string;
  scope?: string;
  created: string;
  modified?: string;
  action_count?: number;
  condition_count?: number;
  technique_count?: number;
  confidence?: number;
  status?: string;
  author?: string;
}

export default function FlowsPage() {
  const [flows, setFlows] = useState<AttackFlow[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const { toast } = useToast();

  useEffect(() => {
    fetchFlows();
    fetchStats();
  }, []);

  const fetchFlows = async () => {
    try {
      // Search for flows
      const response = await fetch("http://localhost:8001/v1/search/flows", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: "",
          top_k: 100,
          filters: {}
        })
      });

      if (response.ok) {
        const data = await response.json();
        setFlows(data.results || []);
      } else {
        // If search doesn't work, try another approach
        setFlows([]);
      }
    } catch (error: any) {
      console.error("Error fetching flows:", error);
      toast({
        title: "Error loading flows",
        description: "Failed to load attack flows",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch("http://localhost:8001/v1/graph/attack_flow");
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error("Error fetching flow stats:", error);
    }
  };

  const getStatusColor = (status?: string) => {
    switch (status) {
      case "active":
        return "bg-green-500/20 text-green-500";
      case "draft":
        return "bg-yellow-500/20 text-yellow-500";
      case "archived":
        return "bg-gray-500/20 text-gray-500";
      default:
        return "bg-blue-500/20 text-blue-500";
    }
  };

  const getConfidenceIcon = (confidence?: number) => {
    if (!confidence) return null;
    if (confidence >= 0.8) return <CheckCircle className="h-4 w-4 text-green-500" />;
    if (confidence >= 0.5) return <Activity className="h-4 w-4 text-yellow-500" />;
    return <AlertTriangle className="h-4 w-4 text-red-500" />;
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
          <h1 className="text-3xl font-bold tracking-tight">Attack Flows</h1>
          <p className="text-muted-foreground">
            Visualize and analyze attack sequences and campaigns
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/flows/builder">
            <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              <Plus className="h-4 w-4" />
              New Flow
            </button>
          </Link>
          <Link href="/flows/simulate">
            <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
              <Play className="h-4 w-4" />
              Simulate
            </button>
          </Link>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Flows</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{flows.length}</div>
            <p className="text-xs text-muted-foreground">
              Attack sequences modeled
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Flows</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {flows.filter(f => f.status === "active").length}
            </div>
            <p className="text-xs text-muted-foreground">
              Currently monitored
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg. Complexity</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {flows.length > 0
                ? Math.round(
                    flows.reduce((sum, f) => sum + (f.action_count || 0), 0) / flows.length
                  )
                : 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Actions per flow
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Confidence</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {flows.filter(f => (f.confidence || 0) >= 0.8).length}
            </div>
            <p className="text-xs text-muted-foreground">
              Well-validated flows
            </p>
          </CardContent>
        </Card>
      </div>

      {flows.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <GitBranch className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium">No attack flows yet</p>
            <p className="text-sm text-muted-foreground mt-2">
              Create your first attack flow to model threat sequences
            </p>
            <Link href="/flows/builder">
              <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
                Create Attack Flow
              </button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Attack Flow Library</h2>
          <div className="grid gap-4">
            {flows.map((flow) => (
              <Link key={flow.flow_id} href={`/flows/${encodeURIComponent(flow.flow_id)}`}>
                <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <GitBranch className="h-5 w-5 text-blue-500" />
                          <CardTitle className="text-lg">{flow.name}</CardTitle>
                          {flow.status && (
                            <Badge className={getStatusColor(flow.status)} variant="secondary">
                              {flow.status}
                            </Badge>
                          )}
                          {getConfidenceIcon(flow.confidence)}
                        </div>
                        {flow.description && (
                          <CardDescription className="mt-2">
                            {flow.description}
                          </CardDescription>
                        )}
                      </div>
                      <ChevronRight className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-6 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Layers className="h-4 w-4" />
                        {flow.action_count || 0} actions
                      </span>
                      {flow.technique_count !== undefined && (
                        <span className="flex items-center gap-1">
                          <Activity className="h-4 w-4" />
                          {flow.technique_count} techniques
                        </span>
                      )}
                      {flow.condition_count !== undefined && flow.condition_count > 0 && (
                        <span className="flex items-center gap-1">
                          <GitBranch className="h-4 w-4" />
                          {flow.condition_count} conditions
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="h-4 w-4" />
                        {format(new Date(flow.created), "MMM d, yyyy")}
                      </span>
                      {flow.author && (
                        <span className="flex items-center gap-1">
                          by {flow.author}
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Import Attack Flow</CardTitle>
          <CardDescription>
            Load an existing Attack Flow from JSON
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <FileJson className="h-8 w-8 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm">
                Import MITRE Attack Flow JSON files or STIX bundles containing flow objects
              </p>
            </div>
            <Link href="/ingest">
              <button className="px-4 py-2 border rounded-md hover:bg-muted">
                Import Flow
              </button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}