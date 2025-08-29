"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Loader2,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  Target,
  GitBranch,
  Plus,
  Search,
  Calendar,
  TrendingUp,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { typedApi } from "@/lib/api-client";

interface Report {
  id: string;
  name: string;
  description?: string;
  published?: string;
  created: string;
  modified: string;
  object_refs: string[];
  campaign_id?: string;
  flow_id?: string;
  entity_counts?: {
    attack_patterns: number;
    intrusion_sets: number;
    software: number;
  };
  extraction_status?: "pending" | "processing" | "completed" | "failed";
  confidence_avg?: number;
}

interface ReportStats {
  total_reports: number;
  with_campaigns: number;
  with_flows: number;
  total_entities: number;
  recent_7_days: number;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<ReportStats | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const { toast } = useToast();

  useEffect(() => {
    fetchReports();
    fetchStats();
  }, [statusFilter]);

  const fetchReports = async () => {
    try {
      const response = await typedApi.reports.list({
        limit: 100,
        status: statusFilter !== "all" ? statusFilter : undefined,
      });
      
      // Transform API response to match our Report interface
      const transformedReports: Report[] = response.reports.map((report: any) => ({
        id: report.report_id,
        name: report.name,
        description: report.description,
        published: report.published,
        created: report.created,
        modified: report.modified,
        object_refs: [],
        campaign_id: report.has_campaign ? `campaign-${report.report_id}` : undefined,
        flow_id: report.has_flow ? `flow-${report.report_id}` : undefined,
        entity_counts: {
          attack_patterns: report.techniques_count,
          intrusion_sets: 0,
          software: 0,
        },
        extraction_status: report.status as any,
        confidence_avg: report.confidence_avg,
      }));
      
      setReports(transformedReports);
    } catch (error) {
      console.error("Error fetching reports:", error);
      toast({
        title: "Error loading reports",
        description: "Failed to load reports list",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await typedApi.reports.getStatistics();
      
      setStats({
        total_reports: response.total_reports,
        with_campaigns: response.with_campaigns,
        with_flows: response.with_flows,
        total_entities: Math.round(response.avg_techniques * response.total_reports),
        recent_7_days: response.recent_7_days,
      });
    } catch (error) {
      console.error("Error fetching stats:", error);
      // Use default stats on error
      setStats({
        total_reports: 0,
        with_campaigns: 0,
        with_flows: 0,
        total_entities: 0,
        recent_7_days: 0,
      });
    }
  };

  const getStatusColor = (status?: string) => {
    switch (status) {
      case "completed":
        return "bg-green-500/20 text-green-500";
      case "processing":
        return "bg-blue-500/20 text-blue-500";
      case "failed":
        return "bg-red-500/20 text-red-500";
      case "pending":
        return "bg-yellow-500/20 text-yellow-500";
      default:
        return "bg-gray-500/20 text-gray-500";
    }
  };

  const getConfidenceIcon = (confidence?: number) => {
    if (!confidence) return null;
    if (confidence >= 80) return <CheckCircle className="h-4 w-4 text-green-500" />;
    if (confidence >= 50) return <Activity className="h-4 w-4 text-yellow-500" />;
    return <AlertTriangle className="h-4 w-4 text-red-500" />;
  };

  const filteredReports = reports.filter((report) => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        report.name.toLowerCase().includes(query) ||
        (report.description && report.description.toLowerCase().includes(query))
      );
    }
    return true;
  }).filter((report) => {
    if (statusFilter === "all") return true;
    if (statusFilter === "with_campaign") return !!report.campaign_id;
    if (statusFilter === "with_flow") return !!report.flow_id;
    return report.extraction_status === statusFilter;
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
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-muted-foreground">
            Threat intelligence reports with extracted entities and campaigns
          </p>
        </div>
        <Link href="/reports/new">
          <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
            <Plus className="h-4 w-4" />
            New Report
          </button>
        </Link>
      </div>

      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Reports</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_reports}</div>
              <p className="text-xs text-muted-foreground">
                Ingested reports
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">With Campaigns</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.with_campaigns}</div>
              <p className="text-xs text-muted-foreground">
                Created campaigns
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">With Flows</CardTitle>
              <GitBranch className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.with_flows}</div>
              <p className="text-xs text-muted-foreground">
                Generated flows
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Entities</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_entities}</div>
              <p className="text-xs text-muted-foreground">
                Extracted entities
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
                Last 7 days
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Report Library</CardTitle>
              <CardDescription>
                Ingested threat intelligence reports with extraction results
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium">Filter:</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-1 border rounded-md"
                >
                  <option value="all">All Reports</option>
                  <option value="with_campaign">With Campaign</option>
                  <option value="with_flow">With Flow</option>
                  <option value="completed">Completed</option>
                  <option value="processing">Processing</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search reports..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="px-3 py-1 border rounded-md"
                />
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredReports.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-medium">No reports found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {reports.length === 0 
                  ? "Start by ingesting your first threat intelligence report"
                  : "No reports match your current filters"}
              </p>
              {reports.length === 0 && (
                <Link href="/reports/new">
                  <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
                    Ingest First Report
                  </button>
                </Link>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {filteredReports.map((report) => (
                <div 
                  key={report.id} 
                  className="flex items-start gap-4 p-4 border rounded-lg hover:bg-muted/50 cursor-pointer"
                  onClick={() => window.location.href = `/reports/${encodeURIComponent(report.id)}/review`}
                >
                  <FileText className="h-5 w-5 text-blue-500 mt-1" />
                  <div className="flex-1">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium">{report.name}</h3>
                          {report.extraction_status && (
                            <Badge className={getStatusColor(report.extraction_status)} variant="secondary">
                              {report.extraction_status}
                            </Badge>
                          )}
                          {getConfidenceIcon(report.confidence_avg)}
                        </div>
                        {report.description && (
                          <p className="text-sm text-muted-foreground mt-1">
                            {report.description}
                          </p>
                        )}
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          {report.published && (
                            <span className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              Published: {format(new Date(report.published), "MMM d, yyyy")}
                            </span>
                          )}
                          {report.entity_counts && (
                            <>
                              <span>{report.entity_counts.attack_patterns} techniques</span>
                              <span>{report.entity_counts.intrusion_sets} actors</span>
                              <span>{report.entity_counts.software} tools</span>
                            </>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          {report.campaign_id && (
                            <Link href={`/campaigns/${report.campaign_id}`} onClick={(e) => e.stopPropagation()}>
                              <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                                <Target className="h-3 w-3 mr-1" />
                                Campaign
                              </Badge>
                            </Link>
                          )}
                          {report.flow_id && (
                            <Link href={`/flows/${report.flow_id}`} onClick={(e) => e.stopPropagation()}>
                              <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                                <GitBranch className="h-3 w-3 mr-1" />
                                Flow
                              </Badge>
                            </Link>
                          )}
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}