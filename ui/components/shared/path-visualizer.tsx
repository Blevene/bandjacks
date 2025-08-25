"use client";

import { SimulationPath } from "@/lib/simulation-types";
import { ArrowRight, Activity } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface PathVisualizerProps {
  path: SimulationPath;
}

export function PathVisualizer({ path }: PathVisualizerProps) {
  return (
    <div className="space-y-3">
      {/* Timeline view */}
      <div className="relative">
        {path.steps.map((step, index) => (
          <div key={index} className="flex items-center mb-3">
            {/* Node */}
            <div className="flex items-center">
              <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                <span className="text-sm font-semibold">{index + 1}</span>
              </div>
            </div>

            {/* Content */}
            <div className="ml-4 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-medium">{step.technique_id}</span>
                {step.technique_name && (
                  <span className="text-sm text-muted-foreground">
                    {step.technique_name}
                  </span>
                )}
              </div>
              
              <div className="flex items-center gap-2 mt-1">
                {step.tactic && (
                  <Badge variant="outline" className="text-xs">
                    {step.tactic}
                  </Badge>
                )}
                {step.probability !== undefined && (
                  <Badge variant="secondary" className="text-xs">
                    <Activity className="h-3 w-3 mr-1" />
                    {(step.probability * 100).toFixed(1)}%
                  </Badge>
                )}
                {step.evidence_count !== undefined && (
                  <span className="text-xs text-muted-foreground">
                    {step.evidence_count} observations
                  </span>
                )}
              </div>
            </div>

            {/* Arrow */}
            {index < path.steps.length - 1 && (
              <ArrowRight className="h-4 w-4 text-muted-foreground mx-2" />
            )}
          </div>
        ))}
      </div>

      {/* Summary Stats */}
      <div className="pt-3 border-t grid grid-cols-3 gap-4 text-sm">
        <div>
          <span className="text-muted-foreground">Total Probability:</span>
          <span className="ml-2 font-medium">
            {(path.total_probability * 100).toFixed(2)}%
          </span>
        </div>
        <div>
          <span className="text-muted-foreground">Complexity Score:</span>
          <span className="ml-2 font-medium">{path.complexity_score.toFixed(2)}</span>
        </div>
        {path.duration_estimate && (
          <div>
            <span className="text-muted-foreground">Est. Duration:</span>
            <span className="ml-2 font-medium">{path.duration_estimate}</span>
          </div>
        )}
      </div>
    </div>
  );
}