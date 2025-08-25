"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useRouter } from "next/navigation";
import {
  Upload,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Settings,
  FileWarning,
  Package,
  Info,
  ArrowRight,
  Target,
  GitBranch,
} from "lucide-react";
import { typedApi } from "@/lib/api-client";

interface IngestConfig {
  use_batch_mapper: boolean;
  skip_verification: boolean;
  force_provisional_campaign: boolean;
  disable_targeted_extraction: boolean;
  max_spans: number;
  confidence_threshold: number;
  auto_generate_flow: boolean;
}

interface IngestResult {
  report_id: string;
  campaign_id?: string;
  flow_id?: string;
  provisional: boolean;
  decisions: {
    rubric: {
      time_bounded: boolean;
      operational_scope: boolean;
      attribution_present: boolean;
      multi_step_activity: boolean;
      criteria_met: number;
      created_campaign: boolean;
      reason: string;
    };
  };
  entities: {
    describes: string[];
    intrusion_sets: string[];
    software: string[];
    attack_patterns: string[];
  };
  rejected: any[];
  warnings: string[];
  trace_id: string;
  extraction_metrics: {
    duration_ms: number;
    spans_found: number;
    techniques_extracted: number;
    confidence_avg: number;
  };
}

export default function NewReportPage() {
  const [textContent, setTextContent] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [ingestResult, setIngestResult] = useState<IngestResult | null>(null);
  const [config, setConfig] = useState<IngestConfig>({
    use_batch_mapper: true,
    skip_verification: false,
    force_provisional_campaign: false,
    disable_targeted_extraction: true,
    max_spans: 10,
    confidence_threshold: 50.0,
    auto_generate_flow: true,
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { toast } = useToast();
  const router = useRouter();

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const allowedTypes = [".pdf", ".txt", ".md", ".markdown"];
    const fileExt = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    
    if (!allowedTypes.includes(fileExt)) {
      toast({
        title: "Invalid File Type",
        description: `Only PDF, TXT, and Markdown files are supported`,
        variant: "destructive",
      });
      return;
    }

    setSelectedFile(file);
    setTextContent(""); // Clear text content when file is selected
  };

  const handleIngest = async () => {
    if (!selectedFile && !textContent.trim()) {
      toast({
        title: "No Content",
        description: "Please upload a file or paste text content",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setIngestResult(null);

    try {
      let result: IngestResult;

      if (selectedFile) {
        // Use file upload endpoint
        result = await typedApi.reports.ingestUpload(selectedFile, {
          use_batch_mapper: config.use_batch_mapper,
          skip_verification: config.skip_verification,
          force_provisional_campaign: config.force_provisional_campaign,
        });
      } else {
        // Use text ingestion endpoint
        result = await typedApi.reports.ingest({
          report_sdo: {
            type: "report",
            spec_version: "2.1",
            name: "Manual Report Entry",
            description: "Report created from pasted text",
            published: new Date().toISOString(),
          },
          inline_text: textContent,
          config: config,
        });
      }

      setIngestResult(result);

      toast({
        title: "Ingestion Complete",
        description: (
          <div className="space-y-1">
            <p>Report processed successfully</p>
            <p className="text-xs">
              {result.extraction_metrics.techniques_extracted} techniques extracted
            </p>
          </div>
        ),
      });

      // Navigate to report detail after short delay
      setTimeout(() => {
        router.push(`/reports/${result.report_id}`);
      }, 2000);

    } catch (error: any) {
      console.error("Ingestion error:", error);
      const traceId = error.response?.data?.trace_id;
      
      toast({
        title: "Ingestion Failed",
        description: (
          <div className="space-y-1">
            <p>{error.response?.data?.detail || "Failed to process report"}</p>
            {traceId && <p className="text-xs text-muted-foreground">Trace: {traceId}</p>}
          </div>
        ),
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const getRubricIcon = (met: boolean) => {
    return met 
      ? <CheckCircle className="h-4 w-4 text-green-500" />
      : <XCircle className="h-4 w-4 text-gray-400" />;
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Ingest Report</h1>
        <p className="text-muted-foreground">
          Extract threat intelligence from reports using advanced NLP
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Report Content</CardTitle>
            <CardDescription>
              Upload a file or paste report text for analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="border-2 border-dashed rounded-lg p-6 text-center hover:border-primary/50 transition-colors">
              <input
                type="file"
                id="file-upload"
                accept=".pdf,.txt,.md,.markdown"
                onChange={handleFileSelect}
                className="hidden"
                disabled={loading}
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center gap-2"
              >
                <Upload className="h-8 w-8 text-muted-foreground" />
                <span className="text-sm font-medium">
                  {selectedFile ? selectedFile.name : "Click to upload"}
                </span>
                <span className="text-xs text-muted-foreground">
                  PDF, TXT, or Markdown files
                </span>
              </label>
            </div>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  Or paste text
                </span>
              </div>
            </div>

            <textarea
              value={textContent}
              onChange={(e) => {
                setTextContent(e.target.value);
                setSelectedFile(null); // Clear file when text is entered
              }}
              placeholder="Paste threat intelligence report text here..."
              className="w-full h-64 p-3 text-sm border rounded-md bg-muted/50 font-mono"
              disabled={loading}
            />

            <div className="flex items-center justify-between">
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
              >
                <Settings className="h-4 w-4" />
                Advanced Settings
              </button>
              
              <button
                onClick={handleIngest}
                disabled={(!selectedFile && !textContent.trim()) || loading}
                className="px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Processing...
                  </>
                ) : (
                  <>
                    <Package className="h-4 w-4" />
                    Ingest Report
                  </>
                )}
              </button>
            </div>

            {showAdvanced && (
              <Card className="bg-muted/30">
                <CardContent className="pt-6 space-y-4">
                  <div className="space-y-3">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={config.use_batch_mapper}
                        onChange={(e) => setConfig({...config, use_batch_mapper: e.target.checked})}
                        className="rounded"
                      />
                      <span className="text-sm">Use batch mapper (faster)</span>
                    </label>
                    
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={config.skip_verification}
                        onChange={(e) => setConfig({...config, skip_verification: e.target.checked})}
                        className="rounded"
                      />
                      <span className="text-sm">Skip evidence verification</span>
                    </label>
                    
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={config.force_provisional_campaign}
                        onChange={(e) => setConfig({...config, force_provisional_campaign: e.target.checked})}
                        className="rounded"
                      />
                      <span className="text-sm">Force provisional campaign creation</span>
                    </label>
                    
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={config.auto_generate_flow}
                        onChange={(e) => setConfig({...config, auto_generate_flow: e.target.checked})}
                        className="rounded"
                      />
                      <span className="text-sm">Auto-generate attack flow</span>
                    </label>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="text-sm">
                      Confidence threshold: {config.confidence_threshold}%
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={config.confidence_threshold}
                      onChange={(e) => setConfig({...config, confidence_threshold: Number(e.target.value)})}
                      className="w-full"
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <label className="text-sm">
                      Max spans to process: {config.max_spans}
                    </label>
                    <input
                      type="range"
                      min="1"
                      max="50"
                      value={config.max_spans}
                      onChange={(e) => setConfig({...config, max_spans: Number(e.target.value)})}
                      className="w-full"
                    />
                  </div>
                </CardContent>
              </Card>
            )}
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Extraction Process</CardTitle>
              <CardDescription>
                How reports are processed
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-start gap-2">
                <FileText className="h-4 w-4 text-blue-500 mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Text Extraction</p>
                  <p className="text-xs text-muted-foreground">
                    Extract and normalize text from PDF/documents
                  </p>
                </div>
              </div>
              
              <div className="flex items-start gap-2">
                <Target className="h-4 w-4 text-green-500 mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Entity Recognition</p>
                  <p className="text-xs text-muted-foreground">
                    Identify techniques, actors, and tools using LLM
                  </p>
                </div>
              </div>
              
              <div className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 text-yellow-500 mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Campaign Rubric</p>
                  <p className="text-xs text-muted-foreground">
                    Evaluate 4 criteria to determine campaign creation
                  </p>
                </div>
              </div>
              
              <div className="flex items-start gap-2">
                <GitBranch className="h-4 w-4 text-purple-500 mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Flow Generation</p>
                  <p className="text-xs text-muted-foreground">
                    Build attack flow from sequenced techniques
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Campaign Creation Criteria</CardTitle>
              <CardDescription>
                At least 2 criteria must be met
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="text-sm space-y-2">
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <span>Time-bounded activity (first/last seen)</span>
                </div>
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <span>Operational scope (multiple techniques)</span>
                </div>
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <span>Attribution present (threat actor)</span>
                </div>
                <div className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  <span>Multi-step activity (sequenced)</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {ingestResult && (
        <Card className="border-green-500/50">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-green-600">Ingestion Successful</CardTitle>
                <CardDescription>
                  Report processed in {ingestResult.extraction_metrics.duration_ms}ms
                </CardDescription>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <p className="text-sm font-medium">Techniques</p>
                <p className="text-2xl font-bold">{ingestResult.entities.attack_patterns.length}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Threat Actors</p>
                <p className="text-2xl font-bold">{ingestResult.entities.intrusion_sets.length}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Tools/Malware</p>
                <p className="text-2xl font-bold">{ingestResult.entities.software.length}</p>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-sm font-medium">Campaign Rubric Evaluation</h4>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex items-center gap-2">
                  {getRubricIcon(ingestResult.decisions.rubric.time_bounded)}
                  <span>Time-bounded</span>
                </div>
                <div className="flex items-center gap-2">
                  {getRubricIcon(ingestResult.decisions.rubric.operational_scope)}
                  <span>Operational scope</span>
                </div>
                <div className="flex items-center gap-2">
                  {getRubricIcon(ingestResult.decisions.rubric.attribution_present)}
                  <span>Attribution</span>
                </div>
                <div className="flex items-center gap-2">
                  {getRubricIcon(ingestResult.decisions.rubric.multi_step_activity)}
                  <span>Multi-step</span>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                {ingestResult.decisions.rubric.reason}
              </p>
            </div>

            <div className="flex items-center gap-2">
              {ingestResult.campaign_id && (
                <Badge variant="outline">
                  <Target className="h-3 w-3 mr-1" />
                  Campaign Created
                  {ingestResult.provisional && " (Provisional)"}
                </Badge>
              )}
              {ingestResult.flow_id && (
                <Badge variant="outline">
                  <GitBranch className="h-3 w-3 mr-1" />
                  Flow Generated
                </Badge>
              )}
            </div>

            {ingestResult.warnings.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Warnings
                </h4>
                <div className="space-y-1">
                  {ingestResult.warnings.map((warning, idx) => (
                    <p key={idx} className="text-xs text-muted-foreground">
                      {warning}
                    </p>
                  ))}
                </div>
              </div>
            )}

            <div className="text-xs text-muted-foreground">
              Trace ID: {ingestResult.trace_id}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}