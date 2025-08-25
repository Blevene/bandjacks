import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Clock, 
  Activity, 
  Shield, 
  Users, 
  Package, 
  AlertTriangle, 
  XCircle,
  TrendingUp,
  Hash,
  FileWarning,
  CheckCircle
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ExtractionMetrics {
  duration_ms: number;
  spans_found: number;
  techniques_extracted: number;
  confidence_avg: number;
}

interface EntityCounts {
  attack_patterns: string[];
  intrusion_sets: string[];
  software: string[];
}

interface RejectedItem {
  id: string;
  reason: string;
}

interface ExtractionResultsProps {
  metrics: ExtractionMetrics;
  entities: EntityCounts;
  rejected?: RejectedItem[];
  warnings?: string[];
  traceId?: string;
  showDetails?: boolean;
  className?: string;
}

export function ExtractionResults({
  metrics,
  entities,
  rejected = [],
  warnings = [],
  traceId,
  showDetails = true,
  className = "",
}: ExtractionResultsProps) {
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return "text-green-500";
    if (confidence >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  const totalEntities = 
    entities.attack_patterns.length + 
    entities.intrusion_sets.length + 
    entities.software.length;

  return (
    <div className={cn("space-y-4", className)}>
      {/* Metrics Summary */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Duration</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatDuration(metrics.duration_ms)}</div>
            <p className="text-xs text-muted-foreground">
              Processing time
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Confidence</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={cn("text-2xl font-bold", getConfidenceColor(metrics.confidence_avg))}>
              {Math.round(metrics.confidence_avg)}%
            </div>
            <p className="text-xs text-muted-foreground">
              Average confidence
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Spans</CardTitle>
            <Hash className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{metrics.spans_found}</div>
            <p className="text-xs text-muted-foreground">
              Text spans analyzed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Entities</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalEntities}</div>
            <p className="text-xs text-muted-foreground">
              Total extracted
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Entity Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>Extracted Entities</CardTitle>
          <CardDescription>
            Threat intelligence entities identified in the report
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Shield className="h-6 w-6 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{entities.attack_patterns.length}</p>
                <p className="text-sm text-muted-foreground">Techniques</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/10 rounded-lg">
                <Users className="h-6 w-6 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{entities.intrusion_sets.length}</p>
                <p className="text-sm text-muted-foreground">Threat Actors</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/10 rounded-lg">
                <Package className="h-6 w-6 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{entities.software.length}</p>
                <p className="text-sm text-muted-foreground">Tools/Malware</p>
              </div>
            </div>
          </div>

          {showDetails && entities.attack_patterns.length > 0 && (
            <div className="mt-4 pt-4 border-t">
              <p className="text-sm font-medium mb-2">Technique IDs</p>
              <div className="flex flex-wrap gap-1">
                {entities.attack_patterns.slice(0, 10).map((id, idx) => (
                  <Badge key={idx} variant="outline" className="text-xs">
                    {id.split("--")[0]}
                  </Badge>
                ))}
                {entities.attack_patterns.length > 10 && (
                  <Badge variant="outline" className="text-xs">
                    +{entities.attack_patterns.length - 10} more
                  </Badge>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Warnings and Rejections */}
      {(warnings.length > 0 || rejected.length > 0) && (
        <Card className="border-yellow-500/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileWarning className="h-5 w-5 text-yellow-500" />
              Issues & Warnings
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {warnings.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Warnings ({warnings.length})
                </p>
                <div className="space-y-1">
                  {warnings.slice(0, 5).map((warning, idx) => (
                    <p key={idx} className="text-xs text-muted-foreground pl-6">
                      • {warning}
                    </p>
                  ))}
                  {warnings.length > 5 && (
                    <p className="text-xs text-muted-foreground pl-6">
                      ... and {warnings.length - 5} more warnings
                    </p>
                  )}
                </div>
              </div>
            )}

            {rejected.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2 flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-500" />
                  Rejected Items ({rejected.length})
                </p>
                <div className="space-y-2">
                  {rejected.slice(0, 3).map((item, idx) => (
                    <div key={idx} className="pl-6 space-y-1">
                      <p className="text-xs font-medium text-red-600">
                        {item.id}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {item.reason}
                      </p>
                    </div>
                  ))}
                  {rejected.length > 3 && (
                    <p className="text-xs text-muted-foreground pl-6">
                      ... and {rejected.length - 3} more rejected items
                    </p>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Success Summary */}
      {rejected.length === 0 && warnings.length === 0 && totalEntities > 0 && (
        <Card className="border-green-500/50 bg-green-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-6 w-6 text-green-500" />
              <div>
                <p className="font-medium">Extraction Successful</p>
                <p className="text-sm text-muted-foreground">
                  All entities extracted and validated successfully
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Trace ID */}
      {traceId && showDetails && (
        <div className="text-xs text-muted-foreground text-center">
          Trace ID: {traceId}
        </div>
      )}
    </div>
  );
}