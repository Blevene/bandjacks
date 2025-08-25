"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingSpinner } from "@/components/shared/loading-spinner";
import { typedApi } from "@/lib/api-client";
import type { SimulationRequest, SimulationPath } from "@/lib/simulation-types";
import { PlayCircle, Target, Users, GitBranch, AlertTriangle } from "lucide-react";
import { PathVisualizer } from "@/components/shared/path-visualizer";

export function PathSimulator() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<SimulationPath[]>([]);
  const [error, setError] = useState<string | null>(null);
  
  const [config, setConfig] = useState<SimulationRequest>({
    max_depth: 5,
    num_paths: 10,
    method: "deterministic",
    include_probabilities: true,
  });

  const [startType, setStartType] = useState<"technique" | "group">("technique");
  const [startValue, setStartValue] = useState("");
  const [targetTechnique, setTargetTechnique] = useState("");

  const handleSimulate = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const request: SimulationRequest = {
        ...config,
        ...(startType === "technique" 
          ? { start_technique: startValue }
          : { start_group: startValue }),
        ...(targetTechnique && { target_technique: targetTechnique }),
      };
      
      const response = await typedApi.simulation.paths(request);
      setResults(response.paths);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Simulation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Simulation Configuration</h3>
        
        <div className="grid grid-cols-2 gap-4">
          {/* Starting Point */}
          <div>
            <label className="block text-sm font-medium mb-2">Starting Point</label>
            <div className="flex gap-2 mb-2">
              <Button
                variant={startType === "technique" ? "default" : "outline"}
                size="sm"
                onClick={() => setStartType("technique")}
              >
                <GitBranch className="h-4 w-4 mr-1" />
                Technique
              </Button>
              <Button
                variant={startType === "group" ? "default" : "outline"}
                size="sm"
                onClick={() => setStartType("group")}
              >
                <Users className="h-4 w-4 mr-1" />
                Threat Group
              </Button>
            </div>
            <input
              type="text"
              className="w-full px-3 py-2 border rounded-md"
              placeholder={startType === "technique" ? "e.g., T1055" : "e.g., G0001"}
              value={startValue}
              onChange={(e) => setStartValue(e.target.value)}
            />
          </div>

          {/* Target */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Target Technique (Optional)
            </label>
            <input
              type="text"
              className="w-full px-3 py-2 border rounded-md"
              placeholder="e.g., T1003"
              value={targetTechnique}
              onChange={(e) => setTargetTechnique(e.target.value)}
            />
          </div>

          {/* Method */}
          <div>
            <label className="block text-sm font-medium mb-2">Simulation Method</label>
            <select
              className="w-full px-3 py-2 border rounded-md"
              value={config.method}
              onChange={(e) => setConfig({ ...config, method: e.target.value as any })}
            >
              <option value="deterministic">Deterministic (Graph Traversal)</option>
              <option value="monte_carlo">Monte Carlo (Probabilistic)</option>
            </select>
          </div>

          {/* Max Depth */}
          <div>
            <label className="block text-sm font-medium mb-2">Max Depth</label>
            <input
              type="number"
              className="w-full px-3 py-2 border rounded-md"
              min={1}
              max={10}
              value={config.max_depth}
              onChange={(e) => setConfig({ ...config, max_depth: parseInt(e.target.value) })}
            />
          </div>

          {/* Number of Paths */}
          <div>
            <label className="block text-sm font-medium mb-2">Number of Paths</label>
            <input
              type="number"
              className="w-full px-3 py-2 border rounded-md"
              min={1}
              max={100}
              value={config.num_paths}
              onChange={(e) => setConfig({ ...config, num_paths: parseInt(e.target.value) })}
            />
          </div>

          {/* Include Probabilities */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="include-probs"
              className="mr-2"
              checked={config.include_probabilities}
              onChange={(e) => setConfig({ ...config, include_probabilities: e.target.checked })}
            />
            <label htmlFor="include-probs" className="text-sm font-medium">
              Include Transition Probabilities
            </label>
          </div>
        </div>

        <Button
          onClick={handleSimulate}
          disabled={loading || (!startValue && !targetTechnique)}
          className="mt-4"
        >
          {loading ? (
            <>
              <LoadingSpinner className="mr-2" />
              Simulating...
            </>
          ) : (
            <>
              <PlayCircle className="h-4 w-4 mr-2" />
              Run Simulation
            </>
          )}
        </Button>
      </Card>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
            <span className="text-red-800">{error}</span>
          </div>
        </div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">
            Simulated Attack Paths ({results.length})
          </h3>
          
          <div className="space-y-4">
            {results.map((path, idx) => (
              <PathDisplay key={path.path_id} path={path} index={idx + 1} />
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function PathDisplay({ path, index }: { path: SimulationPath; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-semibold">Path {index}</span>
            <Badge variant={path.is_hypothetical ? "outline" : "default"}>
              {(path.total_probability * 100).toFixed(1)}% probability
            </Badge>
            {path.confidence_score && (
              <Badge variant={path.confidence_score < 0.5 ? "destructive" : "secondary"}>
                {(path.confidence_score * 100).toFixed(0)}% confidence
              </Badge>
            )}
            <Badge variant="outline">
              Complexity: {path.complexity_score.toFixed(1)}
            </Badge>
          </div>

          <div className="flex flex-wrap gap-1 mb-2">
            {path.covered_tactics.map((tactic) => (
              <Badge key={tactic} variant="secondary" className="text-xs">
                {tactic}
              </Badge>
            ))}
          </div>

          {/* Step summary */}
          <div className="text-sm text-muted-foreground">
            {path.steps.slice(0, 3).map((step, i) => (
              <span key={i}>
                {i > 0 && " → "}
                {step.technique_id}
              </span>
            ))}
            {path.steps.length > 3 && ` ... +${path.steps.length - 3} more`}
          </div>

          {/* Warnings */}
          {path.warnings && path.warnings.length > 0 && (
            <div className="mt-2">
              {path.warnings.map((warning, i) => (
                <div key={i} className="flex items-start gap-2 text-sm text-orange-600">
                  <AlertTriangle className="h-4 w-4 mt-0.5" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Hide" : "Show"} Details
        </Button>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t">
          <PathVisualizer path={path} />
        </div>
      )}
    </Card>
  );
}