"use client";

import { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Upload, 
  FileText, 
  Link, 
  Type, 
  AlertCircle, 
  CheckCircle2,
  Clock,
  FileSearch,
  Sparkles,
  Shield
} from "lucide-react";

interface ReportUploaderProps {
  onIngestionComplete?: (result: any) => void;
}

export function ReportUploader({ onIngestionComplete }: ReportUploaderProps) {
  const [ingestionType, setIngestionType] = useState<"file" | "url" | "text">("file");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  
  // Configuration options
  const [config, setConfig] = useState({
    use_batch_mapper: true,
    skip_verification: false,
    force_provisional_campaign: false,
    disable_targeted_extraction: false,
    max_spans: 512,
    confidence_threshold: 0.7,
    auto_generate_flow: true,
  });

  const { toast } = useToast();

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'text/markdown': ['.md'],
      'text/plain': ['.txt'],
      'application/json': ['.json'],
    },
    maxFiles: 1,
  });

  const simulateProgress = () => {
    const stages = [
      { stage: "Parsing document...", progress: 20 },
      { stage: "Extracting entities...", progress: 40 },
      { stage: "Mapping to ATT&CK...", progress: 60 },
      { stage: "Generating STIX objects...", progress: 80 },
      { stage: "Building attack flow...", progress: 90 },
      { stage: "Finalizing...", progress: 100 },
    ];

    let currentStage = 0;
    const interval = setInterval(() => {
      if (currentStage < stages.length) {
        setStage(stages[currentStage].stage);
        setProgress(stages[currentStage].progress);
        currentStage++;
      } else {
        clearInterval(interval);
      }
    }, 800);

    return () => clearInterval(interval);
  };

  const handleIngest = async () => {
    setLoading(true);
    setProgress(0);
    setStage("Initializing...");

    const cleanup = simulateProgress();

    try {
      let result;

      if (ingestionType === "file" && file) {
        result = await typedApi.reports.ingestUpload(file, config);
      } else if (ingestionType === "url" && url) {
        result = await typedApi.reports.ingest({
          file_url: url,
          config,
        });
      } else if (ingestionType === "text" && text) {
        result = await typedApi.reports.ingest({
          inline_text: text,
          config,
        });
      }

      cleanup();
      setProgress(100);
      setStage("Complete!");

      toast({
        title: "Report Ingested Successfully",
        description: (
          <div className="space-y-1">
            <p>Extracted {result.techniques?.length || 0} techniques</p>
            <p>Created {result.relationships?.length || 0} relationships</p>
            {result.flow_id && <p>Generated attack flow: {result.flow_id}</p>}
          </div>
        ),
      });

      if (onIngestionComplete) {
        onIngestionComplete(result);
      }
    } catch (error: any) {
      cleanup();
      toast({
        variant: "destructive",
        title: "Ingestion Failed",
        description: error.response?.data?.detail || "Failed to process report",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Upload Threat Intelligence Report</CardTitle>
          <CardDescription>
            Process reports to extract adversary behavior and generate structured STIX objects
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={ingestionType} onValueChange={(v) => setIngestionType(v as any)}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="file">
                <FileText className="h-4 w-4 mr-2" />
                File Upload
              </TabsTrigger>
              <TabsTrigger value="url">
                <Link className="h-4 w-4 mr-2" />
                URL
              </TabsTrigger>
              <TabsTrigger value="text">
                <Type className="h-4 w-4 mr-2" />
                Direct Text
              </TabsTrigger>
            </TabsList>

            <TabsContent value="file" className="space-y-4">
              <div
                {...getRootProps()}
                className={`
                  border-2 border-dashed rounded-lg p-8 text-center cursor-pointer
                  transition-colors duration-200
                  ${isDragActive ? "border-primary bg-primary/5" : "border-muted-foreground/25"}
                  ${file ? "bg-muted/50" : "hover:border-primary/50"}
                `}
              >
                <input {...getInputProps()} />
                <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                {file ? (
                  <div className="space-y-2">
                    <p className="font-medium">{file.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {(file.size / 1024).toFixed(1)} KB
                    </p>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFile(null);
                      }}
                    >
                      Remove
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <p className="font-medium">Drop a file here or click to browse</p>
                    <p className="text-sm text-muted-foreground">
                      Supports PDF, Markdown, TXT, and JSON files
                    </p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="url" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">Report URL</Label>
                <Input
                  id="url"
                  type="url"
                  placeholder="https://example.com/threat-report.pdf"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
            </TabsContent>

            <TabsContent value="text" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="text">Report Content</Label>
                <Textarea
                  id="text"
                  placeholder="Paste threat intelligence report text here..."
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  rows={10}
                />
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Advanced Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Processing Configuration</CardTitle>
          <CardDescription>
            Fine-tune how the report is processed and mapped to ATT&CK
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <Switch
                id="batch"
                checked={config.use_batch_mapper}
                onCheckedChange={(checked) => 
                  setConfig({ ...config, use_batch_mapper: checked })
                }
              />
              <Label htmlFor="batch">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4" />
                  Use Batch Mapper
                </div>
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="flow"
                checked={config.auto_generate_flow}
                onCheckedChange={(checked) => 
                  setConfig({ ...config, auto_generate_flow: checked })
                }
              />
              <Label htmlFor="flow">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Auto-Generate Attack Flow
                </div>
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="verification"
                checked={!config.skip_verification}
                onCheckedChange={(checked) => 
                  setConfig({ ...config, skip_verification: !checked })
                }
              />
              <Label htmlFor="verification">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" />
                  Verify Mappings
                </div>
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Switch
                id="campaign"
                checked={config.force_provisional_campaign}
                onCheckedChange={(checked) => 
                  setConfig({ ...config, force_provisional_campaign: checked })
                }
              />
              <Label htmlFor="campaign">
                <div className="flex items-center gap-2">
                  <FileSearch className="h-4 w-4" />
                  Force Provisional Campaign
                </div>
              </Label>
            </div>
          </div>

          <Separator />

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="confidence">
                Confidence Threshold: {config.confidence_threshold}
              </Label>
              <Input
                id="confidence"
                type="range"
                min={0.5}
                max={1}
                step={0.05}
                value={config.confidence_threshold}
                onChange={(e) => 
                  setConfig({ ...config, confidence_threshold: parseFloat(e.target.value) })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="spans">
                Max Spans: {config.max_spans}
              </Label>
              <Input
                id="spans"
                type="number"
                min={128}
                max={2048}
                step={128}
                value={config.max_spans}
                onChange={(e) => 
                  setConfig({ ...config, max_spans: parseInt(e.target.value) })
                }
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Progress Display */}
      {loading && (
        <Card>
          <CardContent className="py-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 animate-spin" />
                  <span className="text-sm font-medium">{stage}</span>
                </div>
                <span className="text-sm text-muted-foreground">{progress}%</span>
              </div>
              <Progress value={progress} />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Action Button */}
      <Button
        onClick={handleIngest}
        disabled={
          loading ||
          (ingestionType === "file" && !file) ||
          (ingestionType === "url" && !url) ||
          (ingestionType === "text" && !text)
        }
        className="w-full"
        size="lg"
      >
        {loading ? (
          <>
            <Clock className="h-4 w-4 mr-2 animate-spin" />
            Processing Report...
          </>
        ) : (
          <>
            <Upload className="h-4 w-4 mr-2" />
            Ingest Report
          </>
        )}
      </Button>

      {/* Info Alert */}
      <Alert>
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Processing Pipeline</AlertTitle>
        <AlertDescription>
          Reports are processed through multiple stages: parsing, entity extraction,
          ATT&CK mapping, STIX generation, and attack flow creation. The system will
          present all extracted objects for review before final integration.
        </AlertDescription>
      </Alert>
    </div>
  );
}