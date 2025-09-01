"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  Database, 
  FileText,
  Clock,
  Shield,
  TrendingUp,
  Loader2
} from "lucide-react";
import { format } from "date-fns";

interface ReportSummary {
  report_id: string;
  name: string;
  created: string;
  status: string;
  techniques_count?: number;
  claims_count?: number;
  confidence_avg?: number;
  has_flow?: boolean;
}

interface GraphStatistics {
  attack_patterns: {
    total: number;
    techniques: number;
    sub_techniques: number;
  };
  threat_groups: {
    total: number;
    active_groups: number;
    total_uses: number;
    avg_techniques_per_group: number;
  };
  attack_flows: {
    total_flows: number;
    total_actions: number;
    avg_actions_per_flow: number;
  };
  defensive_coverage: {
    defense_techniques: number;
    countered_techniques: number;
    coverage_percentage: number;
  };
}

export default function DashboardPage() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [graphStats, setGraphStats] = useState<GraphStatistics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([fetchReports(), fetchGraphStats()]).finally(() => setLoading(false));
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch("http://localhost:8000/v1/reports/");
      if (response.ok) {
        const data = await response.json();
        const reportsList = Array.isArray(data) ? data : (data.reports || []);
        setReports(reportsList);
      }
    } catch (error) {
      console.error("Error fetching reports:", error);
    }
  };

  const fetchGraphStats = async () => {
    try {
      const response = await fetch("http://localhost:8000/v1/analytics/statistics");
      if (response.ok) {
        const data = await response.json();
        setGraphStats(data);
      }
    } catch (error) {
      console.error("Error fetching graph statistics:", error);
    }
  };

  // Calculate real metrics from reports
  const metrics = {
    total_reports: reports.length,
    pending_review: reports.filter(r => r.status === "pending_review").length,
    approved: reports.filter(r => r.status === "approved").length,
    total_techniques: reports.reduce((sum, r) => sum + (r.techniques_count || 0), 0),
    total_claims: reports.reduce((sum, r) => sum + (r.claims_count || 0), 0),
    avg_confidence: reports.length > 0 
      ? reports.reduce((sum, r) => sum + (r.confidence_avg || 0), 0) / reports.filter(r => r.confidence_avg).length
      : 0,
    with_flows: reports.filter(r => r.has_flow).length,
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
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your threat intelligence platform
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Reports
            </CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {metrics.total_reports}
            </div>
            <p className="text-xs text-muted-foreground">
              {metrics.with_flows} with attack flows
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Techniques Extracted
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.total_techniques}</div>
            <p className="text-xs text-muted-foreground">
              {metrics.total_claims} total claims
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Average Confidence
            </CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Math.round(metrics.avg_confidence)}%</div>
            <p className="text-xs text-muted-foreground">
              Extraction confidence
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Pending Review
            </CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.pending_review}</div>
            <p className="text-xs text-muted-foreground">
              {metrics.approved} approved
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Graph Database Statistics */}
      {graphStats && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                ATT&CK Techniques
              </CardTitle>
              <Database className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {graphStats.attack_patterns.total.toLocaleString()}
              </div>
              <p className="text-xs text-muted-foreground">
                {graphStats.attack_patterns.techniques} techniques • {graphStats.attack_patterns.sub_techniques} sub-techniques
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Threat Groups
              </CardTitle>
              <Shield className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{graphStats.threat_groups.total}</div>
              <p className="text-xs text-muted-foreground">
                {graphStats.threat_groups.active_groups} active • {graphStats.threat_groups.avg_techniques_per_group} avg techniques
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Attack Flows
              </CardTitle>
              <Activity className="h-4 w-4 text-purple-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{graphStats.attack_flows.total_flows}</div>
              <p className="text-xs text-muted-foreground">
                {graphStats.attack_flows.total_actions.toLocaleString()} total actions
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Defense Coverage
              </CardTitle>
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{graphStats.defensive_coverage.coverage_percentage}%</div>
              <p className="text-xs text-muted-foreground">
                {graphStats.defensive_coverage.countered_techniques} techniques covered
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Report Statistics</CardTitle>
            <CardDescription>
              Overview of extracted threat intelligence
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-500" />
                  <span className="text-sm font-medium">Total Techniques</span>
                </div>
                <span className="text-2xl font-bold">{metrics.total_techniques}</span>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>Average Confidence</span>
                  <span className="font-medium">
                    {metrics.avg_confidence.toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div 
                    className="bg-green-500 h-2 rounded-full transition-all"
                    style={{ width: `${metrics.avg_confidence}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 pt-4">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Pending</p>
                  <p className="text-xl font-bold">{metrics.pending_review}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Approved</p>
                  <p className="text-xl font-bold">{metrics.approved}</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">With Flows</p>
                  <p className="text-xl font-bold">{metrics.with_flows}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>
              API health and service status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">API Backend</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Healthy</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Neo4j Database</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Connected</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">OpenSearch</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Operational</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm">LLM Service</span>
                </div>
                <span className="text-xs text-yellow-500 font-medium">Rate Limited</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Reports</CardTitle>
          <CardDescription>
            Latest uploaded threat intelligence reports
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {reports.slice(0, 5).map((report) => (
              <div key={report.report_id} className="flex items-center gap-4">
                <div className="flex-shrink-0">
                  <FileText className="h-5 w-5 text-blue-500" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-medium line-clamp-1">{report.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {format(new Date(report.created), "MMM d, h:mm a")} • {report.techniques_count || 0} techniques
                  </p>
                </div>
                <div className="text-right">
                  <span className={`text-xs font-medium ${
                    report.confidence_avg && report.confidence_avg >= 80 ? 'text-green-500' :
                    report.confidence_avg && report.confidence_avg >= 50 ? 'text-yellow-500' :
                    'text-red-500'
                  }`}>
                    {report.confidence_avg ? `${Math.round(report.confidence_avg)}%` : 'N/A'}
                  </span>
                </div>
              </div>
            ))}
            {reports.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">
                No reports uploaded yet
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
