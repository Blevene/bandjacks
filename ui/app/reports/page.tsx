"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  Loader2,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Clock,
  Plus,
  Search,
  Calendar,
  TrendingUp,
  Shield,
  Hash,
  Database,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { useRouter } from "next/navigation";

interface ReportSummary {
  report_id: string;
  name: string;
  description?: string;
  created: string;
  modified: string;
  status: string;
  techniques_count?: number;
  claims_count?: number;
  confidence_avg?: number;
  graph_upserted_at?: string;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const { toast } = useToast();
  const router = useRouter();

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch("http://localhost:8000/v1/reports/");
      if (!response.ok) {
        throw new Error("Failed to fetch reports");
      }
      const data = await response.json();
      console.log("Reports response:", data);
      
      // Handle both array response and object with reports field
      const reportsList = Array.isArray(data) ? data : (data.reports || []);
      setReports(reportsList);
    } catch (error: any) {
      console.error("Error fetching reports:", error);
      toast({
        title: "Error loading reports",
        description: error.message || "Failed to load reports",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const filteredReports = reports.filter(report =>
    report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    report.description?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "approved":
        return <Badge className="bg-green-500">Approved</Badge>;
      case "reviewed":
        return <Badge className="bg-blue-500">Reviewed</Badge>;
      case "pending_review":
        return <Badge variant="secondary">Pending Review</Badge>;
      case "rejected":
        return <Badge variant="destructive">Rejected</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "approved":
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "reviewed":
        return <CheckCircle className="h-4 w-4 text-blue-500" />;
      case "pending_review":
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case "rejected":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return <FileText className="h-4 w-4 text-gray-500" />;
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-muted-foreground">
            Manage and review threat intelligence reports
          </p>
        </div>
        <Button onClick={() => router.push("/reports/new")}>
          <Plus className="h-4 w-4 mr-2" />
          New Report
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Reports</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{reports.length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Review</CardTitle>
            <Clock className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {reports.filter(r => r.status === "pending_review").length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Techniques</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {reports.reduce((sum, r) => sum + (r.techniques_count || 0), 0)}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">In Graph</CardTitle>
            <Database className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {reports.filter(r => r.graph_upserted_at).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <Card>
        <CardHeader>
          <CardTitle>Search Reports</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by name or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9"
            />
          </div>
        </CardContent>
      </Card>

      {/* Reports List */}
      <div className="grid gap-4">
        {filteredReports.length === 0 ? (
          <Card>
            <CardContent className="py-8 text-center">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-medium">No reports found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {searchTerm
                  ? "Try adjusting your search criteria"
                  : "Upload your first report to get started"}
              </p>
              {!searchTerm && (
                <Button className="mt-4" onClick={() => router.push("/reports/new")}>
                  <Plus className="h-4 w-4 mr-2" />
                  Upload Report
                </Button>
              )}
            </CardContent>
          </Card>
        ) : (
          filteredReports.map((report) => (
            <Link
              key={report.report_id}
              href={`/reports/${report.report_id}`}
              className="block"
            >
              <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      {getStatusIcon(report.status)}
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold">{report.name}</h3>
                          {getStatusBadge(report.status)}
                          {report.graph_upserted_at && (
                            <Badge className="bg-purple-600" title={`Graph updated: ${format(new Date(report.graph_upserted_at), "MMM d, yyyy HH:mm")}`}>
                              <Database className="h-3 w-3 mr-1" />
                              In Graph
                            </Badge>
                          )}
                        </div>
                        {report.description && (
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {report.description}
                          </p>
                        )}
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <div className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {format(new Date(report.created), "MMM d, yyyy")}
                          </div>
                          {report.techniques_count !== undefined && (
                            <div className="flex items-center gap-1">
                              <Shield className="h-3 w-3" />
                              {report.techniques_count} techniques
                            </div>
                          )}
                          {report.claims_count !== undefined && (
                            <div className="flex items-center gap-1">
                              <Hash className="h-3 w-3" />
                              {report.claims_count} claims
                            </div>
                          )}
                          {report.confidence_avg !== undefined && (
                            <div className="flex items-center gap-1">
                              <TrendingUp className="h-3 w-3" />
                              {Math.round(report.confidence_avg)}% confidence
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground mt-1" />
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}