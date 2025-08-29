"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useParams, useRouter } from "next/navigation";
import {
  FileText,
  Loader2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Target,
  GitBranch,
  Calendar,
  Activity,
  Info,
  ExternalLink,
  Shield,
  Users,
  Package,
  ChevronRight,
  Clock,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { typedApi } from "@/lib/api-client";

interface ReportDetail {
  id: string;
  type: string;
  spec_version: string;
  name: string;
  description?: string;
  published?: string;
  created: string;
  modified: string;
  object_refs: string[];
  external_references?: any[];
  x_bj_provenance?: {
    extraction_method: string;
    extracted_at: string;
    rubric_evaluation: {
      time_bounded: boolean;
      operational_scope: boolean;
      attribution_present: boolean;
      multi_step_activity: boolean;
      criteria_met: number;
      created_campaign: boolean;
      reason: string;
      first_seen?: string;
      last_seen?: string;
    };
    rubric_evidence?: {
      time_bounds_detected: Array<{
        text: string;
        first_seen?: string;
        last_seen?: string;
      }>;
      distinct_techniques: string[];
      intrusion_sets: Array<{
        name: string;
        confidence: number;
        evidence: any;
      }>;
      sequence_cues: string[];
      confidence_scores: Record<string, number>;
    };
  };
  relationships?: {
    describes: RelatedEntity[];
    campaigns: RelatedEntity[];
    flows: RelatedEntity[];
  };
}

interface RelatedEntity {
  id: string;
  type: string;
  name: string;
  description?: string;
  external_id?: string;
  confidence?: number;
  evidence?: {
    spans: string[];
    context?: string;
  };
}

export default function ReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const reportId = params.id as string;
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"entities" | "rubric" | "evidence">("entities");
  const { toast } = useToast();

  useEffect(() => {
    if (reportId) {
      fetchReport();
    }
  }, [reportId]);

  const fetchReport = async () => {
    try {
      const data = await typedApi.reports.get(reportId);
      // API returns { report: {...}, entities: {...}, campaign: {...} }
      // Extract and merge the data for the component
      const reportWithEntities = {
        ...data.report,
        id: data.report.stix_id, // Map stix_id to id
        entities: data.entities,
        campaign: data.campaign,
        // Map entities to relationships format expected by UI
        relationships: {
          describes: [
            ...(data.entities?.attack_patterns || []),
            ...(data.entities?.intrusion_sets || []),
            ...(data.entities?.software || [])
          ]
        }
      };
      setReport(reportWithEntities);
    } catch (error: any) {
      console.error("Error fetching report:", error);
      toast({
        title: "Error loading report",
        description: error.response?.data?.detail || "Failed to load report details",
        variant: "destructive",
      });
      // Navigate back to reports list if report not found
      if (error.response?.status === 404) {
        setTimeout(() => router.push("/reports"), 2000);
      }
    } finally {
      setLoading(false);
    }
  };

  const getEntityIcon = (type: string) => {
    switch (type) {
      case "attack-pattern":
        return <Shield className="h-4 w-4 text-blue-500" />;
      case "intrusion-set":
        return <Users className="h-4 w-4 text-red-500" />;
      case "tool":
      case "malware":
        return <Package className="h-4 w-4 text-purple-500" />;
      case "campaign":
        return <Target className="h-4 w-4 text-orange-500" />;
      case "attack-flow":
        return <GitBranch className="h-4 w-4 text-green-500" />;
      default:
        return <Activity className="h-4 w-4 text-gray-500" />;
    }
  };

  const getEntityTypeName = (type: string) => {
    switch (type) {
      case "attack-pattern":
        return "Technique";
      case "intrusion-set":
        return "Threat Actor";
      case "tool":
        return "Tool";
      case "malware":
        return "Malware";
      case "campaign":
        return "Campaign";
      case "attack-flow":
        return "Attack Flow";
      default:
        return type;
    }
  };

  const getRubricIcon = (met: boolean) => {
    return met 
      ? <CheckCircle className="h-5 w-5 text-green-500" />
      : <XCircle className="h-5 w-5 text-gray-400" />;
  };

  const getConfidenceColor = (confidence?: number) => {
    if (!confidence) return "text-gray-500";
    if (confidence >= 80) return "text-green-500";
    if (confidence >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-lg font-medium">Report not found</p>
        <p className="text-sm text-muted-foreground mt-2">
          The requested report could not be found
        </p>
      </div>
    );
  }

  const rubric = report.x_bj_provenance?.rubric_evaluation;
  const techniques = report.relationships?.describes?.filter(e => e.type === "attack-pattern") || [];
  const actors = report.relationships?.describes?.filter(e => e.type === "intrusion-set") || [];
  const software = report.relationships?.describes?.filter(e => e.type === "tool" || e.type === "malware") || [];
  const campaigns = report.relationships?.campaigns || [];
  const flows = report.relationships?.flows || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
            <Link href="/reports" className="hover:text-foreground">
              Reports
            </Link>
            <ChevronRight className="h-4 w-4" />
            <span className="text-foreground">{report.name}</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <FileText className="h-8 w-8 text-blue-500" />
            {report.name}
          </h1>
          {report.description && (
            <p className="text-muted-foreground mt-2">{report.description}</p>
          )}
        </div>
        <div className="flex flex-col gap-2 items-end">
          {/* Review button for pending extraction results */}
          {report.x_bj_provenance?.extraction_method && techniques.length > 0 && (
            <Button
              onClick={() => router.push(`/reports/${report.id}/review`)}
              variant="default"
              className="flex items-center gap-2"
            >
              <Shield className="h-4 w-4" />
              Review Extraction ({techniques.length} techniques)
            </Button>
          )}
          {campaigns.length > 0 && (
            <Link href={`/campaigns/${campaigns[0].id}`}>
              <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                <Target className="h-3 w-3 mr-1" />
                View Campaign
              </Badge>
            </Link>
          )}
          {flows.length > 0 && (
            <Link href={`/flows/${flows[0].id}`}>
              <Badge variant="outline" className="cursor-pointer hover:bg-muted">
                <GitBranch className="h-3 w-3 mr-1" />
                View Flow
              </Badge>
            </Link>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Techniques</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{techniques.length}</div>
            <p className="text-xs text-muted-foreground">
              ATT&CK techniques
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threat Actors</CardTitle>
            <Users className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{actors.length}</div>
            <p className="text-xs text-muted-foreground">
              Intrusion sets
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Software</CardTitle>
            <Package className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{software.length}</div>
            <p className="text-xs text-muted-foreground">
              Tools & malware
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Published</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm font-medium">
              {report.published 
                ? (report.published ? format(new Date(report.published), "MMM d, yyyy") : "N/A")
                : "Unknown"}
            </div>
            <p className="text-xs text-muted-foreground">
              Report date
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Extraction</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm font-medium">
              {report.x_bj_provenance?.extracted_at 
                ? (report.x_bj_provenance.extracted_at ? format(new Date(report.x_bj_provenance.extracted_at), "MMM d, yyyy") : "N/A")
                : "Manual"}
            </div>
            <p className="text-xs text-muted-foreground">
              {report.x_bj_provenance?.extraction_method || "No extraction"}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab("entities")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "entities"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Extracted Entities
        </button>
        <button
          onClick={() => setActiveTab("rubric")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "rubric"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Campaign Rubric
        </button>
        <button
          onClick={() => setActiveTab("evidence")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "evidence"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Evidence & Context
        </button>
      </div>

      {activeTab === "entities" && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Attack Techniques</CardTitle>
              <CardDescription>
                {techniques.length} techniques identified
              </CardDescription>
            </CardHeader>
            <CardContent>
              {techniques.length === 0 ? (
                <p className="text-sm text-muted-foreground">No techniques extracted</p>
              ) : (
                <div className="space-y-3">
                  {techniques.map((technique) => (
                    <div key={technique.id} className="flex items-start gap-3">
                      <Shield className="h-5 w-5 text-blue-500 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Link href={`/techniques/${technique.external_id || technique.id}`}>
                            <p className="font-medium hover:text-blue-500 cursor-pointer">
                              {technique.name}
                            </p>
                          </Link>
                          {technique.external_id && (
                            <Badge variant="outline" className="text-xs">
                              {technique.external_id}
                            </Badge>
                          )}
                          {technique.confidence && (
                            <span className={`text-xs font-medium ${getConfidenceColor(technique.confidence)}`}>
                              {technique.confidence}%
                            </span>
                          )}
                        </div>
                        {technique.description && (
                          <p className="text-xs text-muted-foreground mt-1">
                            {technique.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat Actors & Software</CardTitle>
              <CardDescription>
                {actors.length + software.length} entities identified
              </CardDescription>
            </CardHeader>
            <CardContent>
              {actors.length === 0 && software.length === 0 ? (
                <p className="text-sm text-muted-foreground">No actors or software extracted</p>
              ) : (
                <div className="space-y-3">
                  {actors.map((actor) => (
                    <div key={actor.id} className="flex items-start gap-3">
                      <Users className="h-5 w-5 text-red-500 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{actor.name}</p>
                          {actor.confidence && (
                            <span className={`text-xs font-medium ${getConfidenceColor(actor.confidence)}`}>
                              {actor.confidence}%
                            </span>
                          )}
                        </div>
                        {actor.description && (
                          <p className="text-xs text-muted-foreground mt-1">
                            {actor.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                  {software.map((tool) => (
                    <div key={tool.id} className="flex items-start gap-3">
                      <Package className="h-5 w-5 text-purple-500 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{tool.name}</p>
                          <Badge variant="outline" className="text-xs">
                            {tool.type === "malware" ? "Malware" : "Tool"}
                          </Badge>
                          {tool.confidence && (
                            <span className={`text-xs font-medium ${getConfidenceColor(tool.confidence)}`}>
                              {tool.confidence}%
                            </span>
                          )}
                        </div>
                        {tool.description && (
                          <p className="text-xs text-muted-foreground mt-1">
                            {tool.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === "rubric" && rubric && (
        <Card>
          <CardHeader>
            <CardTitle>Campaign Creation Rubric</CardTitle>
            <CardDescription>
              {rubric.criteria_met}/4 criteria met • {rubric.reason}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="flex items-start gap-3">
                {getRubricIcon(rubric.time_bounded)}
                <div>
                  <p className="font-medium">Time-Bounded Activity</p>
                  <p className="text-sm text-muted-foreground">
                    {rubric.time_bounded 
                      ? `Activity spans from ${rubric.first_seen ? format(new Date(rubric.first_seen), "MMM yyyy") : "unknown"} to ${rubric.last_seen ? format(new Date(rubric.last_seen), "MMM yyyy") : "unknown"}`
                      : "No time bounds identified"}
                  </p>
                  {report.x_bj_provenance?.rubric_evidence?.time_bounds_detected && report.x_bj_provenance.rubric_evidence.time_bounds_detected.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {report.x_bj_provenance.rubric_evidence.time_bounds_detected.slice(0, 2).map((tb: any, idx: number) => (
                        <p key={idx} className="text-xs text-muted-foreground/70 italic">
                          "{tb.text.substring(0, 50)}..."
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-start gap-3">
                {getRubricIcon(rubric.operational_scope)}
                <div>
                  <p className="font-medium">Operational Scope</p>
                  <p className="text-sm text-muted-foreground">
                    {rubric.operational_scope 
                      ? `${techniques.length} techniques detected across operation`
                      : "Single or no techniques detected"}
                  </p>
                  {report.x_bj_provenance?.rubric_evidence?.distinct_techniques && report.x_bj_provenance.rubric_evidence.distinct_techniques.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {report.x_bj_provenance.rubric_evidence.distinct_techniques.slice(0, 3).map((tech: any, idx: number) => (
                        <Badge key={idx} variant="outline" className="text-xs">
                          {tech}
                        </Badge>
                      ))}
                      {report.x_bj_provenance.rubric_evidence.distinct_techniques.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{report.x_bj_provenance.rubric_evidence.distinct_techniques.length - 3}
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-start gap-3">
                {getRubricIcon(rubric.attribution_present)}
                <div>
                  <p className="font-medium">Attribution Present</p>
                  <p className="text-sm text-muted-foreground">
                    {rubric.attribution_present 
                      ? `${actors.length} threat actor(s) identified`
                      : "No threat actors identified"}
                  </p>
                  {report.x_bj_provenance?.rubric_evidence?.intrusion_sets && report.x_bj_provenance.rubric_evidence.intrusion_sets.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {report.x_bj_provenance.rubric_evidence.intrusion_sets.map((is: any, idx: number) => (
                        <div key={idx} className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">
                            {is.name}
                          </Badge>
                          <span className={`text-xs ${getConfidenceColor(is.confidence * 100)}`}>
                            {Math.round(is.confidence * 100)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-start gap-3">
                {getRubricIcon(rubric.multi_step_activity)}
                <div>
                  <p className="font-medium">Multi-Step Activity</p>
                  <p className="text-sm text-muted-foreground">
                    {rubric.multi_step_activity 
                      ? "Sequenced activity detected"
                      : "No sequential patterns found"}
                  </p>
                  {report.x_bj_provenance?.rubric_evidence?.sequence_cues && report.x_bj_provenance.rubric_evidence.sequence_cues.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {report.x_bj_provenance.rubric_evidence.sequence_cues.map((cue: any, idx: number) => (
                        <Badge key={idx} variant="secondary" className="text-xs">
                          {cue}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-muted p-4 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Info className="h-4 w-4 text-muted-foreground" />
                <p className="text-sm font-medium">Decision</p>
              </div>
              <p className="text-sm text-muted-foreground">
                {rubric.created_campaign 
                  ? `Campaign created with ${rubric.criteria_met}/4 criteria met. ${campaigns[0]?.name || "Campaign"} was established to track this coordinated activity.`
                  : `Campaign not created. Only ${rubric.criteria_met}/4 criteria met (minimum 2 required). This report describes individual observations without sufficient evidence of coordinated campaign activity.`}
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "evidence" && (
        <Card>
          <CardHeader>
            <CardTitle>Evidence & Context</CardTitle>
            <CardDescription>
              Supporting evidence for extracted entities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[...techniques, ...actors, ...software].map((entity) => (
                entity.evidence?.spans && entity.evidence.spans.length > 0 && (
                  <div key={entity.id} className="border-l-2 border-muted pl-4">
                    <div className="flex items-center gap-2 mb-2">
                      {getEntityIcon(entity.type)}
                      <p className="font-medium">{entity.name}</p>
                      <Badge variant="outline" className="text-xs">
                        {getEntityTypeName(entity.type)}
                      </Badge>
                    </div>
                    <div className="space-y-2">
                      {entity.evidence.spans.map((span, idx) => (
                        <blockquote key={idx} className="text-sm text-muted-foreground italic border-l-2 border-muted pl-3">
                          "{span}"
                        </blockquote>
                      ))}
                    </div>
                  </div>
                )
              ))}
              {[...techniques, ...actors, ...software].every(e => !e.evidence?.spans?.length) && (
                <p className="text-sm text-muted-foreground text-center py-8">
                  No evidence snippets available
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="bg-muted/30">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Report ID: {report.id}</span>
            <span>STIX {report.spec_version}</span>
            <span>Modified: {report.modified ? format(new Date(report.modified), "MMM d, yyyy HH:mm") : "N/A"}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}