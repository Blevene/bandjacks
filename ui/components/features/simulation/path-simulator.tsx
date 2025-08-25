"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
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
      <Card>
        <CardHeader>
          <CardTitle>Simulation Configuration</CardTitle>
          <CardDescription>
            Configure attack path simulation parameters
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Starting Point */}
          <div className="space-y-2">
            <Label>Starting Point</Label>
            <Tabs value={startType} onValueChange={(v) => setStartType(v as any)}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="technique">
                  <GitBranch className="h-4 w-4 mr-2" />
                  Technique
                </TabsTrigger>
                <TabsTrigger value="group">
                  <Users className="h-4 w-4 mr-2" />
                  Threat Group
                </TabsTrigger>
              </TabsList>
            </Tabs>
            <Input
              placeholder={startType === "technique" ? "e.g., T1055" : "e.g., G0001"}
              value={startValue}
              onChange={(e) => setStartValue(e.target.value)}
            />
          </div>

          {/* Target */}
          <div className="space-y-2">
            <Label htmlFor="target">Target Technique (Optional)</Label>
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-muted-foreground" />
              <Input
                id="target"
                placeholder="e.g., T1003"
                value={targetTechnique}
                onChange={(e) => setTargetTechnique(e.target.value)}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Method */}
            <div className="space-y-2">
              <Label htmlFor="method">Simulation Method</Label>
              <Select
                value={config.method}
                onValueChange={(value) => setConfig({ ...config, method: value as any })}
              >
                <SelectTrigger id="method">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="deterministic">Deterministic (Graph Traversal)</SelectItem>
                  <SelectItem value="monte_carlo">Monte Carlo (Probabilistic)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Max Depth */}
            <div className="space-y-2">
              <Label htmlFor="depth">Max Depth</Label>
              <Input
                id="depth"
                type="number"
                min={1}
                max={10}
                value={config.max_depth}
                onChange={(e) => setConfig({ ...config, max_depth: parseInt(e.target.value) })}
              />
            </div>

            {/* Number of Paths */}
            <div className="space-y-2">
              <Label htmlFor="paths">Number of Paths</Label>
              <Input
                id="paths"
                type="number"
                min={1}
                max={100}
                value={config.num_paths}
                onChange={(e) => setConfig({ ...config, num_paths: parseInt(e.target.value) })}
              />
            </div>

            {/* Include Probabilities */}
            <div className="flex items-center space-x-2">
              <Switch
                id="probabilities"
                checked={config.include_probabilities}
                onCheckedChange={(checked) => setConfig({ ...config, include_probabilities: checked })}
              />
              <Label htmlFor="probabilities">Include Transition Probabilities</Label>
            </div>
          </div>

          <Button
            onClick={handleSimulate}
            disabled={loading || (!startValue && !targetTechnique)}
            className="w-full"
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
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Results */}
      {loading && (
        <Card>
          <CardContent className="py-12">
            <div className="space-y-4">
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          </CardContent>
        </Card>
      )}

      {!loading && results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Simulated Attack Paths</CardTitle>
            <CardDescription>
              Found {results.length} possible attack paths
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {results.map((path, idx) => (
              <PathDisplay key={path.path_id} path={path} index={idx + 1} />
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function PathDisplay({ path, index }: { path: SimulationPath; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardContent className="pt-6">
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
              <Alert variant="destructive" className="mt-2">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  {path.warnings.map((warning, i) => (
                    <div key={i}>{warning}</div>
                  ))}
                </AlertDescription>
              </Alert>
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
      </CardContent>
    </Card>
  );
}