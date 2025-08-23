"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Upload,
  FileJson,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  ChevronRight,
  FileWarning,
  Package
} from "lucide-react";

export default function IngestPage() {
  const [bundleContent, setBundleContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [ingestResult, setIngestResult] = useState<any>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const { toast } = useToast();

  const validateBundle = (content: string): boolean => {
    setValidationErrors([]);
    const errors: string[] = [];

    try {
      const bundle = JSON.parse(content);
      
      if (bundle.type !== "bundle") {
        errors.push("Object must be a STIX bundle (type: 'bundle')");
      }
      
      if (!bundle.id || !bundle.id.startsWith("bundle--")) {
        errors.push("Bundle must have a valid ID starting with 'bundle--'");
      }
      
      if (!Array.isArray(bundle.objects)) {
        errors.push("Bundle must contain an 'objects' array");
      } else if (bundle.objects.length === 0) {
        errors.push("Bundle objects array cannot be empty");
      }
      
      if (bundle.spec_version && bundle.spec_version !== "2.1") {
        errors.push("Only STIX 2.1 bundles are supported");
      }
    } catch (e) {
      errors.push("Invalid JSON format");
    }

    setValidationErrors(errors);
    return errors.length === 0;
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setBundleContent(content);
      validateBundle(content);
    };
    reader.readAsText(file);
  };

  const handleIngest = async () => {
    if (!validateBundle(bundleContent)) {
      toast({
        title: "Validation Failed",
        description: "Please fix the validation errors before ingesting",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setIngestResult(null);

    try {
      const bundle = JSON.parse(bundleContent);
      const result = await typedApi.stix.ingestBundle(bundle, true);
      
      setIngestResult(result);
      
      toast({
        title: "Ingestion Complete",
        description: `Processed ${result.total_objects || 0} objects`,
      });
    } catch (error: any) {
      const traceId = error.response?.data?.trace_id;
      toast({
        title: "Ingestion Failed",
        description: (
          <div className="space-y-1">
            <p>{error.response?.data?.detail || "Failed to ingest bundle"}</p>
            {traceId && <p className="text-xs text-muted-foreground">Trace: {traceId}</p>}
          </div>
        ),
        variant: "destructive",
      });
      
      // Parse rejection details if available
      if (error.response?.data?.rejections) {
        setIngestResult({
          rejected: error.response.data.rejections.length,
          rejections: error.response.data.rejections,
          inserted: 0,
          updated: 0,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Bundle Ingestion</h1>
        <p className="text-muted-foreground">
          Upload and validate STIX 2.1 bundles with ADM compliance
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Upload Bundle</CardTitle>
            <CardDescription>
              Select a STIX 2.1 bundle file or paste JSON content
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="border-2 border-dashed rounded-lg p-6 text-center hover:border-primary/50 transition-colors">
              <input
                type="file"
                id="file-upload"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center gap-2"
              >
                <Upload className="h-8 w-8 text-muted-foreground" />
                <span className="text-sm font-medium">Click to upload</span>
                <span className="text-xs text-muted-foreground">
                  or drag and drop a STIX bundle
                </span>
              </label>
            </div>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  Or paste JSON
                </span>
              </div>
            </div>

            <textarea
              value={bundleContent}
              onChange={(e) => {
                setBundleContent(e.target.value);
                if (e.target.value) validateBundle(e.target.value);
              }}
              placeholder='{"type": "bundle", "id": "bundle--...", "objects": [...]}'
              className="w-full h-48 p-3 text-sm font-mono border rounded-md bg-muted/50"
            />

            {validationErrors.length > 0 && (
              <div className="space-y-2">
                {validationErrors.map((error, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                    <span className="text-muted-foreground">{error}</span>
                  </div>
                ))}
              </div>
            )}

            <button
              onClick={handleIngest}
              disabled={!bundleContent || loading || validationErrors.length > 0}
              className="w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  <Package className="h-4 w-4" />
                  Ingest Bundle
                </>
              )}
            </button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Validation Requirements</CardTitle>
            <CardDescription>
              All bundles must meet these criteria
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-start gap-2">
              <FileJson className="h-4 w-4 text-blue-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium">STIX 2.1 Format</p>
                <p className="text-xs text-muted-foreground">
                  Bundle must conform to STIX 2.1 specification
                </p>
              </div>
            </div>
            
            <div className="flex items-start gap-2">
              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium">ADM Compliance</p>
                <p className="text-xs text-muted-foreground">
                  ATT&CK objects must pass ADM validation
                </p>
              </div>
            </div>
            
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium">Source Tracking</p>
                <p className="text-xs text-muted-foreground">
                  All objects tagged with provenance metadata
                </p>
              </div>
            </div>
            
            <div className="flex items-start gap-2">
              <XCircle className="h-4 w-4 text-red-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium">Rejection Handling</p>
                <p className="text-xs text-muted-foreground">
                  Invalid objects rejected with detailed reasons
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {ingestResult && (
        <Card>
          <CardHeader>
            <CardTitle>Ingestion Results</CardTitle>
            <CardDescription>
              Summary of processed objects
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3 mb-4">
              <div className="flex items-center gap-3">
                <CheckCircle className="h-5 w-5 text-green-500" />
                <div>
                  <p className="text-2xl font-bold">{ingestResult.inserted || 0}</p>
                  <p className="text-xs text-muted-foreground">Inserted</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                <ChevronRight className="h-5 w-5 text-blue-500" />
                <div>
                  <p className="text-2xl font-bold">{ingestResult.updated || 0}</p>
                  <p className="text-xs text-muted-foreground">Updated</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                <FileWarning className="h-5 w-5 text-yellow-500" />
                <div>
                  <p className="text-2xl font-bold">{ingestResult.rejected || 0}</p>
                  <p className="text-xs text-muted-foreground">Rejected</p>
                </div>
              </div>
            </div>

            {ingestResult.rejections && ingestResult.rejections.length > 0 && (
              <div className="space-y-2 pt-4 border-t">
                <h4 className="text-sm font-medium">Rejection Details</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {ingestResult.rejections.map((rejection: any, idx: number) => (
                    <div key={idx} className="p-3 bg-muted rounded-md">
                      <div className="flex items-start gap-2">
                        <XCircle className="h-4 w-4 text-red-500 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {rejection.object_id || rejection.id || `Object ${idx + 1}`}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {rejection.reason || rejection.error || "Validation failed"}
                          </p>
                          {rejection.details && (
                            <pre className="text-xs mt-2 p-2 bg-background rounded overflow-x-auto">
                              {JSON.stringify(rejection.details, null, 2)}
                            </pre>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}