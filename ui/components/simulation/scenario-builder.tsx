"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingSpinner } from "@/components/shared/loading-spinner";
import { typedApi } from "@/lib/api-client";
import type { ScenarioSimulationRequest, SimulationResponse } from "@/lib/simulation-types";
import { Users, Package, GitBranch, PlayCircle, Target } from "lucide-react";
import { PathVisualizer } from "@/components/shared/path-visualizer";

export function ScenarioBuilder() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<SimulationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [intrusionSets, setIntrusionSets] = useState<string[]>([]);
  const [software, setSoftware] = useState<string[]>([]);
  const [techniques, setTechniques] = useState<string[]>([]);
  const [targetTechnique, setTargetTechnique] = useState("");
  
  const [newIntrusionSet, setNewIntrusionSet] = useState("");
  const [newSoftware, setNewSoftware] = useState("");
  const [newTechnique, setNewTechnique] = useState("");
  
  const [config, setConfig] = useState({
    max_starting_points: 5,
    max_depth: 5,
    num_paths: 10,
    method: "deterministic" as const,
    include_probabilities: true,
  });

  const addIntrusionSet = () => {
    if (newIntrusionSet && !intrusionSets.includes(newIntrusionSet)) {
      setIntrusionSets([...intrusionSets, newIntrusionSet]);
      setNewIntrusionSet("");
    }
  };

  const addSoftware = () => {
    if (newSoftware && !software.includes(newSoftware)) {
      setSoftware([...software, newSoftware]);
      setNewSoftware("");
    }
  };

  const addTechnique = () => {
    if (newTechnique && !techniques.includes(newTechnique)) {
      setTechniques([...techniques, newTechnique]);
      setNewTechnique("");
    }
  };

  const handleSimulate = async () => {
    if (intrusionSets.length === 0 && software.length === 0 && techniques.length === 0) {
      setError("Please add at least one intrusion set, software, or technique");
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      const request: ScenarioSimulationRequest = {
        intrusion_sets: intrusionSets.length > 0 ? intrusionSets : undefined,
        software: software.length > 0 ? software : undefined,
        techniques: techniques.length > 0 ? techniques : undefined,
        target_technique: targetTechnique || undefined,
        ...config,
      };
      
      const response = await typedApi.simulation.scenario(request);
      setResults(response);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Scenario simulation failed");
    } finally {
      setLoading(false);
    }
  };

  const totalInputs = intrusionSets.length + software.length + techniques.length;

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Scenario Configuration</h3>
        
        <div className="grid grid-cols-3 gap-4 mb-4">
          {/* Intrusion Sets */}
          <div>
            <label className="block text-sm font-medium mb-2">
              <Users className="h-4 w-4 inline mr-1" />
              Intrusion Sets
            </label>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                className="flex-1 px-3 py-2 border rounded-md text-sm"
                placeholder="e.g., G0001"
                value={newIntrusionSet}
                onChange={(e) => setNewIntrusionSet(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && addIntrusionSet()}
              />
              <Button onClick={addIntrusionSet} size="sm">Add</Button>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {intrusionSets.map((item) => (
                <Badge key={item} variant="outline" className="mr-1">
                  {item}
                  <button
                    className="ml-1"
                    onClick={() => setIntrusionSets(intrusionSets.filter(i => i !== item))}
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          </div>

          {/* Software */}
          <div>
            <label className="block text-sm font-medium mb-2">
              <Package className="h-4 w-4 inline mr-1" />
              Software/Malware
            </label>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                className="flex-1 px-3 py-2 border rounded-md text-sm"
                placeholder="e.g., S0001"
                value={newSoftware}
                onChange={(e) => setNewSoftware(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && addSoftware()}
              />
              <Button onClick={addSoftware} size="sm">Add</Button>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {software.map((item) => (
                <Badge key={item} variant="outline" className="mr-1">
                  {item}
                  <button
                    className="ml-1"
                    onClick={() => setSoftware(software.filter(i => i !== item))}
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          </div>

          {/* Techniques */}
          <div>
            <label className="block text-sm font-medium mb-2">
              <GitBranch className="h-4 w-4 inline mr-1" />
              Known Techniques
            </label>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                className="flex-1 px-3 py-2 border rounded-md text-sm"
                placeholder="e.g., T1055"
                value={newTechnique}
                onChange={(e) => setNewTechnique(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && addTechnique()}
              />
              <Button onClick={addTechnique} size="sm">Add</Button>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {techniques.map((item) => (
                <Badge key={item} variant="outline" className="mr-1">
                  {item}
                  <button
                    className="ml-1"
                    onClick={() => setTechniques(techniques.filter(i => i !== item))}
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          </div>
        </div>

        {/* Advanced Options */}
        <div className="grid grid-cols-4 gap-4 pt-4 border-t">
          <div>
            <label className="block text-sm font-medium mb-1">Target Technique</label>
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                className="flex-1 px-2 py-1 border rounded-md text-sm"
                placeholder="Optional"
                value={targetTechnique}
                onChange={(e) => setTargetTechnique(e.target.value)}
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1">Max Starting Points</label>
            <input
              type="number"
              className="w-full px-2 py-1 border rounded-md text-sm"
              min={1}
              max={50}
              value={config.max_starting_points}
              onChange={(e) => setConfig({ ...config, max_starting_points: parseInt(e.target.value) })}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1">Max Depth</label>
            <input
              type="number"
              className="w-full px-2 py-1 border rounded-md text-sm"
              min={1}
              max={10}
              value={config.max_depth}
              onChange={(e) => setConfig({ ...config, max_depth: parseInt(e.target.value) })}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1">Simulation Method</label>
            <select
              className="w-full px-2 py-1 border rounded-md text-sm"
              value={config.method}
              onChange={(e) => setConfig({ ...config, method: e.target.value as any })}
            >
              <option value="deterministic">Deterministic</option>
              <option value="monte_carlo">Monte Carlo</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between mt-4">
          <div className="text-sm text-muted-foreground">
            {totalInputs} input{totalInputs !== 1 ? 's' : ''} configured
          </div>
          <Button
            onClick={handleSimulate}
            disabled={loading || totalInputs === 0}
          >
            {loading ? (
              <>
                <LoadingSpinner className="mr-2" />
                Simulating...
              </>
            ) : (
              <>
                <PlayCircle className="h-4 w-4 mr-2" />
                Run Scenario
              </>
            )}
          </Button>
        </div>
      </Card>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <span className="text-red-800">{error}</span>
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary */}
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Scenario Results</h3>
            
            {results.summary.starting_points && (
              <div className="mb-4">
                <p className="text-sm text-muted-foreground mb-2">
                  Starting techniques derived from inputs:
                </p>
                <div className="flex flex-wrap gap-1">
                  {results.summary.starting_points.map((tech) => (
                    <Badge key={tech} variant="secondary">
                      {tech}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            
            <div className="grid grid-cols-3 gap-4 text-center">
              <div className="p-3 bg-muted/50 rounded-md">
                <div className="text-2xl font-bold">{results.summary.paths_returned}</div>
                <div className="text-sm text-muted-foreground">Paths Found</div>
              </div>
              <div className="p-3 bg-muted/50 rounded-md">
                <div className="text-2xl font-bold">{results.summary.method}</div>
                <div className="text-sm text-muted-foreground">Method Used</div>
              </div>
              <div className="p-3 bg-muted/50 rounded-md">
                <div className="text-2xl font-bold">{results.summary.max_depth}</div>
                <div className="text-sm text-muted-foreground">Max Depth</div>
              </div>
            </div>
          </Card>

          {/* Attack Paths */}
          {results.paths.length > 0 && (
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">
                Generated Attack Paths
              </h3>
              <div className="space-y-4">
                {results.paths.slice(0, 5).map((path, idx) => (
                  <Card key={path.path_id} className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <span className="font-medium">Path {idx + 1}</span>
                        <Badge variant="secondary">
                          {(path.total_probability * 100).toFixed(1)}% probability
                        </Badge>
                        <Badge variant="outline">
                          {path.steps.length} steps
                        </Badge>
                      </div>
                    </div>
                    <PathVisualizer path={path} />
                  </Card>
                ))}
                {results.paths.length > 5 && (
                  <p className="text-sm text-muted-foreground text-center">
                    ... and {results.paths.length - 5} more paths
                  </p>
                )}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}