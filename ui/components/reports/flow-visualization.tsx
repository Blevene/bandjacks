"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  GitBranch,
  ArrowRight,
  AlertTriangle,
  Activity,
  Shuffle,
  Zap,
} from "lucide-react";
import type { AttackFlow, FlowStep, FlowEdge } from "@/lib/report-types";

interface FlowVisualizationProps {
  flow: AttackFlow;
}

export function FlowVisualization({ flow }: FlowVisualizationProps) {
  if (!flow || flow.steps.length === 0) {
    return (
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          No attack flow data available for this report.
        </AlertDescription>
      </Alert>
    );
  }

  // Create adjacency map from edges
  const edgeMap: Record<string, FlowEdge[]> = {};
  flow.edges.forEach(edge => {
    if (!edgeMap[edge.source]) {
      edgeMap[edge.source] = [];
    }
    // Default relationship to NEXT if not specified
    const edgeWithRelation = {
      ...edge,
      relationship: edge.relationship || 'NEXT' as const
    };
    edgeMap[edge.source].push(edgeWithRelation);
  });

  const getFlowTypeIcon = (type: string) => {
    switch (type) {
      case 'llm_synthesized':
        return <Zap className="h-4 w-4" />;
      case 'sequential':
        return <ArrowRight className="h-4 w-4" />;
      case 'co_occurrence':
        return <Shuffle className="h-4 w-4" />;
      default:
        return <Activity className="h-4 w-4" />;
    }
  };

  const getFlowTypeLabel = (type: string) => {
    switch (type) {
      case 'llm_synthesized':
        return 'LLM Synthesized';
      case 'sequential':
        return 'Sequential';
      case 'co_occurrence':
        return 'Co-occurrence';
      default:
        return 'Manual';
    }
  };

  const getProbabilityColor = (probability: number) => {
    if (probability >= 0.8) return 'text-green-500';
    if (probability >= 0.5) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getProbabilityWidth = (probability: number) => {
    if (probability >= 0.8) return 'border-2';
    if (probability >= 0.5) return 'border';
    return 'border border-dashed';
  };

  return (
    <div className="space-y-4">
      {/* Flow metadata */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitBranch className="h-5 w-5" />
            Attack Flow Analysis
          </CardTitle>
          <CardDescription>
            {flow.flow_name || 'Extracted Attack Flow'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Flow Type</p>
              <div className="flex items-center gap-2 mt-1">
                {getFlowTypeIcon(flow.flow_type)}
                <span className="font-medium">{getFlowTypeLabel(flow.flow_type)}</span>
              </div>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Confidence</p>
              <div className="flex items-center gap-2 mt-1">
                <span className={`font-medium ${getProbabilityColor(flow.confidence)}`}>
                  {Math.round(flow.confidence * 100)}%
                </span>
                <Badge variant={flow.confidence >= 0.7 ? 'default' : 'secondary'}>
                  {flow.confidence >= 0.7 ? 'HIGH' : flow.confidence >= 0.4 ? 'MEDIUM' : 'LOW'}
                </Badge>
              </div>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Complexity</p>
              <p className="font-medium mt-1">
                {flow.steps.length} steps, {flow.edges.length} edges
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Flow visualization */}
      <Card>
        <CardHeader>
          <CardTitle>Attack Sequence</CardTitle>
          <CardDescription>
            Temporal progression of techniques in the attack
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {flow.steps.map((step, idx) => {
              // Use action_id or fall back to step_id for backward compatibility
              const stepId = step.action_id || step.step_id || `step-${idx}`;
              const techniqueId = step.attack_pattern_ref || step.technique_id || 'unknown';
              const outgoingEdges = edgeMap[stepId] || [];
              
              return (
                <div key={stepId} className="relative">
                  {/* Step card */}
                  <div className="flex items-start gap-4">
                    <div className="flex-shrink-0 w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center text-sm font-medium">
                      {step.order ?? idx + 1}
                    </div>
                    <Card className="flex-1">
                      <CardContent className="pt-4">
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline">
                                {techniqueId.startsWith('attack-pattern--') ? 
                                  techniqueId.split('--')[1].substring(0, 8) : 
                                  techniqueId}
                              </Badge>
                              <span className="font-medium">{step.name}</span>
                              {step.confidence && (
                                <Badge variant="secondary" className="ml-2">
                                  {Math.round(step.confidence)}% conf
                                </Badge>
                              )}
                            </div>
                          </div>
                          {step.description && (
                            <p className="text-sm text-muted-foreground line-clamp-2">
                              {step.description}
                            </p>
                          )}
                          {step.reason && (
                            <p className="text-xs text-muted-foreground italic">
                              Rationale: {step.reason}
                            </p>
                          )}
                          {step.evidence && step.evidence.length > 0 && (
                            <div className="pt-2 border-t">
                              <p className="text-xs font-medium text-muted-foreground mb-1">Evidence:</p>
                              {step.evidence.slice(0, 2).map((ev, evIdx) => {
                                // Handle both object and string evidence formats
                                const evidenceText = typeof ev === 'string' 
                                  ? ev 
                                  : (ev as any).text || '';
                                
                                if (!evidenceText) return null;
                                
                                return (
                                  <blockquote key={evIdx} className="text-xs italic text-muted-foreground border-l-2 border-muted pl-2">
                                    "{evidenceText.substring(0, 100)}..."
                                  </blockquote>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Edges to next steps */}
                  {outgoingEdges.length > 0 && idx < flow.steps.length - 1 && (
                    <div className="ml-4 mt-2 mb-2">
                      {outgoingEdges.map((edge, edgeIdx) => {
                        const targetStep = flow.steps.find(s => 
                          (s.action_id || s.step_id) === edge.target
                        );
                        if (!targetStep) return null;

                        return (
                          <div key={edgeIdx} className="flex items-center gap-2 py-2">
                            <div className={`flex-1 ${getProbabilityWidth(edge.probability)} border-muted-foreground/30`} />
                            <div className="flex items-center gap-2 text-xs">
                              <Badge variant="secondary" className="text-xs">
                                {edge.relationship}
                              </Badge>
                              <span className={getProbabilityColor(edge.probability)}>
                                {Math.round(edge.probability * 100)}%
                              </span>
                              {edge.rationale && (
                                <span className="text-muted-foreground italic">
                                  ({edge.rationale})
                                </span>
                              )}
                            </div>
                            <ArrowRight className="h-4 w-4 text-muted-foreground" />
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Flow summary */}
          {flow.flow_type === 'llm_synthesized' && (
            <Alert className="mt-4">
              <Zap className="h-4 w-4" />
              <AlertDescription>
                This flow was synthesized by analyzing temporal and causal relationships in the document.
                The sequence represents the most likely progression based on the extracted evidence.
              </AlertDescription>
            </Alert>
          )}
          
          {flow.flow_type === 'co_occurrence' && (
            <Alert className="mt-4">
              <Shuffle className="h-4 w-4" />
              <AlertDescription>
                This represents a co-occurrence pattern where techniques were observed together
                but without clear temporal ordering. Edges indicate likelihood of techniques appearing together.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
}