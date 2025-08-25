"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  TrendingUp,
  TrendingDown,
  Target,
  Users,
  Layers,
  AlertTriangle,
  Activity,
  BarChart3,
  Loader2,
  Download,
  Calendar,
  Info
} from "lucide-react";
import Link from "next/link";

interface CoverageStats {
  summary: {
    total_techniques: number;
    covered_techniques: number;
    coverage_percentage: number;
    total_detections: number;
    avg_detections_per_technique: number;
  };
  tactics: Array<{
    tactic: string;
    technique_count: number;
    covered_count: number;
    coverage_percentage: number;
    top_gaps: Array<{
      technique_id: string;
      technique_name: string;
      priority: string;
    }>;
  }>;
  platforms: Array<{
    platform: string;
    technique_count: number;
    covered_count: number;
    coverage_percentage: number;
    tactics_breakdown: Record<string, number>;
  }>;
  groups: Array<{
    group_id: string;
    group_name: string;
    techniques_used: number;
    techniques_covered: number;
    coverage_percentage: number;
    uncovered_techniques: Array<{
      technique_id: string;
      technique_name: string;
    }>;
  }>;
  recommendations: Array<{
    priority: string;
    technique_id: string;
    technique_name: string;
    reason: string;
    impact: string;
  }>;
}

interface TrendData {
  metric: string;
  period: string;
  data_points: Array<{
    date: string;
    value: number;
    label?: string;
  }>;
  trend_direction: string;
  change_percentage: number;
  insights: string[];
}

export default function AnalyticsPage() {
  const [coverageStats, setCoverageStats] = useState<CoverageStats | null>(null);
  const [trendData, setTrendData] = useState<TrendData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedPeriod, setSelectedPeriod] = useState("30d");
  const [selectedMetric, setSelectedMetric] = useState("coverage");
  const { toast } = useToast();

  useEffect(() => {
    fetchCoverageStats();
    fetchTrendData();
  }, [selectedPeriod, selectedMetric]);

  const fetchCoverageStats = async () => {
    try {
      const response = await fetch("http://localhost:8001/v1/analytics/coverage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          include_sub_techniques: true,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setCoverageStats(data);
      }
    } catch (error) {
      console.error("Error fetching coverage stats:", error);
      toast({
        title: "Error",
        description: "Failed to load coverage statistics",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchTrendData = async () => {
    try {
      const response = await fetch("http://localhost:8001/v1/analytics/trends", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          metric: selectedMetric,
          period: selectedPeriod,
          granularity: selectedPeriod === "7d" ? "daily" : "weekly",
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setTrendData(data);
      }
    } catch (error) {
      console.error("Error fetching trend data:", error);
    }
  };

  const getCoverageColor = (percentage: number) => {
    if (percentage >= 80) return "text-green-500";
    if (percentage >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-500";
      case "high":
        return "bg-orange-500/20 text-orange-500";
      case "medium":
        return "bg-yellow-500/20 text-yellow-500";
      case "low":
        return "bg-green-500/20 text-green-500";
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics Dashboard</h1>
          <p className="text-muted-foreground">
            Coverage analysis and threat intelligence metrics
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/coverage">
            <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
              <Layers className="h-4 w-4" />
              Coverage Heatmap
            </button>
          </Link>
          <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
            <Download className="h-4 w-4" />
            Export Report
          </button>
        </div>
      </div>

      {coverageStats && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Overall Coverage</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${getCoverageColor(coverageStats.summary.coverage_percentage)}`}>
                  {coverageStats.summary.coverage_percentage.toFixed(1)}%
                </div>
                <p className="text-xs text-muted-foreground">
                  {coverageStats.summary.covered_techniques} of {coverageStats.summary.total_techniques} techniques
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Detections</CardTitle>
                <Target className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{coverageStats.summary.total_detections}</div>
                <p className="text-xs text-muted-foreground">
                  Avg {coverageStats.summary.avg_detections_per_technique.toFixed(1)} per technique
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Coverage Gaps</CardTitle>
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-500">
                  {coverageStats.summary.total_techniques - coverageStats.summary.covered_techniques}
                </div>
                <p className="text-xs text-muted-foreground">
                  Techniques without detection
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Trend</CardTitle>
                {trendData?.trend_direction === "up" ? (
                  <TrendingUp className="h-4 w-4 text-green-500" />
                ) : (
                  <TrendingDown className="h-4 w-4 text-red-500" />
                )}
              </CardHeader>
              <CardContent>
                <div className={`text-2xl font-bold ${trendData?.trend_direction === "up" ? "text-green-500" : "text-red-500"}`}>
                  {trendData?.change_percentage ? `${trendData.change_percentage > 0 ? "+" : ""}${trendData.change_percentage.toFixed(1)}%` : "N/A"}
                </div>
                <p className="text-xs text-muted-foreground">
                  {selectedPeriod} change
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Coverage by Tactic</CardTitle>
                    <CardDescription>Detection coverage across ATT&CK tactics</CardDescription>
                  </div>
                  <BarChart3 className="h-5 w-5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {coverageStats.tactics.slice(0, 7).map((tactic) => (
                    <div key={tactic.tactic} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{tactic.tactic}</span>
                        <span className={`text-sm font-medium ${getCoverageColor(tactic.coverage_percentage)}`}>
                          {tactic.coverage_percentage.toFixed(0)}%
                        </span>
                      </div>
                      <div className="w-full bg-muted rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            tactic.coverage_percentage >= 80
                              ? "bg-green-500"
                              : tactic.coverage_percentage >= 50
                              ? "bg-yellow-500"
                              : "bg-red-500"
                          }`}
                          style={{ width: `${tactic.coverage_percentage}%` }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {tactic.covered_count} of {tactic.technique_count} techniques covered
                      </p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Top Priority Gaps</CardTitle>
                    <CardDescription>Techniques requiring immediate attention</CardDescription>
                  </div>
                  <AlertTriangle className="h-5 w-5 text-muted-foreground" />
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {coverageStats.recommendations.slice(0, 6).map((rec, index) => (
                    <div key={index} className="flex items-start gap-3 p-3 border rounded-md">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Link href={`/techniques/${rec.technique_id}`}>
                            <span className="font-medium text-sm hover:text-primary cursor-pointer">
                              {rec.technique_name}
                            </span>
                          </Link>
                          <Badge className={getPriorityColor(rec.priority)} variant="secondary">
                            {rec.priority}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{rec.reason}</p>
                        <p className="text-xs text-blue-500 mt-1">Impact: {rec.impact}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Coverage Trends</CardTitle>
                  <CardDescription>Historical coverage and detection metrics</CardDescription>
                </div>
                <div className="flex gap-2">
                  <select
                    value={selectedMetric}
                    onChange={(e) => setSelectedMetric(e.target.value)}
                    className="px-3 py-1 border rounded-md text-sm"
                  >
                    <option value="coverage">Coverage</option>
                    <option value="detections">Detections</option>
                    <option value="flows">Attack Flows</option>
                  </select>
                  <select
                    value={selectedPeriod}
                    onChange={(e) => setSelectedPeriod(e.target.value)}
                    className="px-3 py-1 border rounded-md text-sm"
                  >
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                    <option value="90d">Last 90 days</option>
                  </select>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {trendData && trendData.insights.length > 0 && (
                <div className="mb-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-md">
                  <div className="flex gap-2">
                    <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-blue-900 dark:text-blue-100">
                        Key Insights
                      </p>
                      <ul className="text-xs text-blue-700 dark:text-blue-300 mt-1 space-y-1">
                        {trendData.insights.map((insight, i) => (
                          <li key={i}>• {insight}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
              
              <div className="h-64 flex items-center justify-center text-muted-foreground">
                <div className="text-center">
                  <Activity className="h-12 w-12 mx-auto mb-2" />
                  <p className="text-sm">Chart visualization would go here</p>
                  <p className="text-xs mt-1">
                    {trendData?.data_points.length || 0} data points available
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Group Coverage Analysis</CardTitle>
              <CardDescription>Detection coverage for tracked threat groups</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {coverageStats.groups.slice(0, 5).map((group) => (
                  <div key={group.group_id} className="flex items-center justify-between p-3 border rounded-md">
                    <div className="flex-1">
                      <p className="font-medium">{group.group_name}</p>
                      <p className="text-sm text-muted-foreground">
                        {group.techniques_covered} of {group.techniques_used} techniques covered
                      </p>
                    </div>
                    <div className="text-right">
                      <p className={`text-lg font-bold ${getCoverageColor(group.coverage_percentage)}`}>
                        {group.coverage_percentage.toFixed(0)}%
                      </p>
                      {group.uncovered_techniques.length > 0 && (
                        <Link href={`/coverage/groups/${group.group_id}`}>
                          <span className="text-xs text-blue-500 hover:text-blue-600 cursor-pointer">
                            View gaps →
                          </span>
                        </Link>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}