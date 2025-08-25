import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, XCircle, Info, Calendar, Activity, Users, GitBranch } from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

export interface RubricData {
  time_bounded: boolean;
  operational_scope: boolean;
  attribution_present: boolean;
  multi_step_activity: boolean;
  criteria_met: number;
  created_campaign: boolean;
  reason: string;
  first_seen?: string;
  last_seen?: string;
}

export interface RubricEvidence {
  time_bounds_detected?: Array<{
    text: string;
    first_seen?: string;
    last_seen?: string;
  }>;
  distinct_techniques?: string[];
  intrusion_sets?: Array<{
    name: string;
    confidence: number;
    evidence?: any;
  }>;
  sequence_cues?: string[];
  confidence_scores?: Record<string, number>;
}

interface RubricEvaluationProps {
  rubric: RubricData;
  evidence?: RubricEvidence;
  showDetails?: boolean;
  compact?: boolean;
  className?: string;
}

export function RubricEvaluation({
  rubric,
  evidence,
  showDetails = true,
  compact = false,
  className = "",
}: RubricEvaluationProps) {
  const getRubricIcon = (met: boolean, size: "sm" | "md" = "md") => {
    const sizeClass = size === "sm" ? "h-4 w-4" : "h-5 w-5";
    return met 
      ? <CheckCircle className={cn(sizeClass, "text-green-500")} />
      : <XCircle className={cn(sizeClass, "text-gray-400")} />;
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return "text-green-500";
    if (confidence >= 50) return "text-yellow-500";
    return "text-red-500";
  };

  if (compact) {
    return (
      <div className={cn("space-y-2", className)}>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            {getRubricIcon(rubric.time_bounded, "sm")}
            <Calendar className="h-3 w-3 text-muted-foreground" />
          </div>
          <div className="flex items-center gap-1">
            {getRubricIcon(rubric.operational_scope, "sm")}
            <Activity className="h-3 w-3 text-muted-foreground" />
          </div>
          <div className="flex items-center gap-1">
            {getRubricIcon(rubric.attribution_present, "sm")}
            <Users className="h-3 w-3 text-muted-foreground" />
          </div>
          <div className="flex items-center gap-1">
            {getRubricIcon(rubric.multi_step_activity, "sm")}
            <GitBranch className="h-3 w-3 text-muted-foreground" />
          </div>
        </div>
        <div className="text-sm text-muted-foreground">
          {rubric.criteria_met}/4 criteria • {rubric.created_campaign ? "Campaign created" : "No campaign"}
        </div>
      </div>
    );
  }

  return (
    <Card className={className}>
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
            <div className="flex-1">
              <p className="font-medium">Time-Bounded Activity</p>
              <p className="text-sm text-muted-foreground">
                {rubric.time_bounded 
                  ? `Activity spans from ${rubric.first_seen ? format(new Date(rubric.first_seen), "MMM yyyy") : "unknown"} to ${rubric.last_seen ? format(new Date(rubric.last_seen), "MMM yyyy") : "unknown"}`
                  : "No time bounds identified"}
              </p>
              {showDetails && evidence?.time_bounds_detected && evidence.time_bounds_detected.length > 0 && (
                <div className="mt-2 space-y-1">
                  {evidence.time_bounds_detected.slice(0, 2).map((tb, idx) => (
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
            <div className="flex-1">
              <p className="font-medium">Operational Scope</p>
              <p className="text-sm text-muted-foreground">
                {rubric.operational_scope 
                  ? `Multiple techniques detected across operation`
                  : "Single or no techniques detected"}
              </p>
              {showDetails && evidence?.distinct_techniques && evidence.distinct_techniques.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {evidence.distinct_techniques.slice(0, 3).map((tech, idx) => (
                    <Badge key={idx} variant="outline" className="text-xs">
                      {tech}
                    </Badge>
                  ))}
                  {evidence.distinct_techniques.length > 3 && (
                    <Badge variant="outline" className="text-xs">
                      +{evidence.distinct_techniques.length - 3}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-start gap-3">
            {getRubricIcon(rubric.attribution_present)}
            <div className="flex-1">
              <p className="font-medium">Attribution Present</p>
              <p className="text-sm text-muted-foreground">
                {rubric.attribution_present 
                  ? "Threat actor(s) identified"
                  : "No threat actors identified"}
              </p>
              {showDetails && evidence?.intrusion_sets && evidence.intrusion_sets.length > 0 && (
                <div className="mt-2 space-y-1">
                  {evidence.intrusion_sets.map((is, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">
                        {is.name}
                      </Badge>
                      <span className={cn("text-xs", getConfidenceColor(is.confidence * 100))}>
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
            <div className="flex-1">
              <p className="font-medium">Multi-Step Activity</p>
              <p className="text-sm text-muted-foreground">
                {rubric.multi_step_activity 
                  ? "Sequenced activity detected"
                  : "No sequential patterns found"}
              </p>
              {showDetails && evidence?.sequence_cues && evidence.sequence_cues.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {evidence.sequence_cues.map((cue, idx) => (
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
              ? `Campaign created with ${rubric.criteria_met}/4 criteria met. A campaign was established to track this coordinated activity.`
              : `Campaign not created. Only ${rubric.criteria_met}/4 criteria met (minimum 2 required). This report describes individual observations without sufficient evidence of coordinated campaign activity.`}
          </p>
        </div>

        {showDetails && (
          <div className="pt-2 border-t">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Minimum criteria required: 2</span>
              <span className={cn(
                "font-medium",
                rubric.criteria_met >= 2 ? "text-green-500" : "text-red-500"
              )}>
                {rubric.criteria_met >= 2 ? "✓ Threshold met" : "✗ Below threshold"}
              </span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}