"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingSpinner } from "@/components/shared/loading-spinner";
import { typedApi } from "@/lib/api-client";
import type { WhatIfRequest, WhatIfResponse, SimulationPath } from "@/lib/simulation-types";
import { Shield, Ban, CheckCircle, AlertTriangle, TrendingDown } from "lucide-react";

export function WhatIfAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<WhatIfResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [scenario, setScenario] = useState("");
  const [blockedTechniques, setBlockedTechniques] = useState<string[]>([]);
  const [requiredTechniques, setRequiredTechniques] = useState<string[]>([]);
  const [newBlocked, setNewBlocked] = useState("");
  const [newRequired, setNewRequired] = useState("");

  const addBlocked = () => {
    if (newBlocked && !blockedTechniques.includes(newBlocked)) {
      setBlockedTechniques([...blockedTechniques, newBlocked]);
      setNewBlocked("");
    }
  };

  const addRequired = () => {
    if (newRequired && !requiredTechniques.includes(newRequired)) {
      setRequiredTechniques([...requiredTechniques, newRequired]);
      setNewRequired("");
    }
  };

  const handleAnalyze = async () => {
    if (!scenario) {
      setError("Please provide a scenario description");
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      const request: WhatIfRequest = {
        scenario,
        blocked_techniques: blockedTechniques.length > 0 ? blockedTechniques : undefined,
        required_techniques: requiredTechniques.length > 0 ? requiredTechniques : undefined,
      };
      
      const response = await typedApi.simulation.whatif(request);
      setResults(response);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Defensive Scenario Configuration</h3>
        
        <div className="space-y-4">
          {/* Scenario Description */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Scenario Description
            </label>
            <textarea
              className="w-full px-3 py-2 border rounded-md"
              rows={3}
              placeholder="Describe the defensive scenario you want to analyze..."
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Blocked Techniques */}
            <div>
              <label className="block text-sm font-medium mb-2">
                <Ban className="h-4 w-4 inline mr-1" />
                Blocked Techniques
              </label>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  className="flex-1 px-3 py-2 border rounded-md"
                  placeholder="e.g., T1055"
                  value={newBlocked}
                  onChange={(e) => setNewBlocked(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && addBlocked()}
                />
                <Button onClick={addBlocked} size="sm">Add</Button>
              </div>
              {blockedTechniques.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {blockedTechniques.map((tech) => (
                    <Badge key={tech} variant="destructive">
                      {tech}
                      <button
                        className="ml-1"
                        onClick={() => setBlockedTechniques(blockedTechniques.filter(t => t !== tech))}
                      >
                        ×
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Required Techniques */}
            <div>
              <label className="block text-sm font-medium mb-2">
                <CheckCircle className="h-4 w-4 inline mr-1" />
                Required Techniques
              </label>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  className="flex-1 px-3 py-2 border rounded-md"
                  placeholder="e.g., T1003"
                  value={newRequired}
                  onChange={(e) => setNewRequired(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && addRequired()}
                />
                <Button onClick={addRequired} size="sm">Add</Button>
              </div>
              {requiredTechniques.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {requiredTechniques.map((tech) => (
                    <Badge key={tech} variant="default">
                      {tech}
                      <button
                        className="ml-1"
                        onClick={() => setRequiredTechniques(requiredTechniques.filter(t => t !== tech))}
                      >
                        ×
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <Button
          onClick={handleAnalyze}
          disabled={loading || !scenario}
          className="mt-4"
        >
          {loading ? (
            <>
              <LoadingSpinner className="mr-2" />
              Analyzing...
            </>
          ) : (
            <>
              <Shield className="h-4 w-4 mr-2" />
              Analyze Scenario
            </>
          )}
        </Button>
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
          {/* Impact Summary */}
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Defensive Impact Analysis</h3>
            
            {results.blocked_impact && (
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="text-center p-4 bg-red-50 rounded-md">
                  <TrendingDown className="h-8 w-8 text-red-500 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-red-700">
                    {results.blocked_impact.paths_blocked}
                  </div>
                  <div className="text-sm text-red-600">Paths Blocked</div>
                </div>
                
                <div className="text-center p-4 bg-green-50 rounded-md">
                  <Shield className="h-8 w-8 text-green-500 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-green-700">
                    {results.blocked_impact.coverage_reduction.toFixed(1)}%
                  </div>
                  <div className="text-sm text-green-600">Coverage Reduction</div>
                </div>
                
                <div className="text-center p-4 bg-blue-50 rounded-md">
                  <AlertTriangle className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-blue-700">
                    {results.blocked_impact.paths_remaining}
                  </div>
                  <div className="text-sm text-blue-600">Paths Remaining</div>
                </div>
              </div>
            )}

            <div className="p-3 bg-muted/50 rounded-md">
              <p className="text-sm">{results.analysis}</p>
            </div>
          </Card>

          {/* Recommendations */}
          {results.recommendations.length > 0 && (
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Recommendations</h3>
              <div className="space-y-3">
                {results.recommendations.map((rec, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-muted/30 rounded-md">
                    <Badge
                      variant={
                        rec.priority === "high" ? "destructive" :
                        rec.priority === "medium" ? "default" :
                        "secondary"
                      }
                    >
                      {rec.priority}
                    </Badge>
                    <div className="flex-1">
                      <p className="font-medium text-sm">{rec.recommendation}</p>
                      <p className="text-sm text-muted-foreground mt-1">{rec.impact}</p>
                      {rec.rationale && (
                        <p className="text-xs text-muted-foreground mt-1">
                          Rationale: {rec.rationale}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Viable Paths */}
          {results.viable_paths.length > 0 && (
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">
                Viable Attack Paths ({results.viable_paths.length})
              </h3>
              <div className="space-y-3">
                {results.viable_paths.slice(0, 5).map((path, idx) => (
                  <PathSummary key={idx} path={path} index={idx + 1} />
                ))}
                {results.viable_paths.length > 5 && (
                  <p className="text-sm text-muted-foreground text-center">
                    ... and {results.viable_paths.length - 5} more paths
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

function PathSummary({ path, index }: { path: SimulationPath; index: number }) {
  return (
    <div className="flex items-center gap-3 p-3 bg-muted/20 rounded-md">
      <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
        <span className="text-sm font-semibold">{index}</span>
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">
            {path.steps.map(s => s.technique_id).join(" → ")}
          </span>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <Badge variant="outline" className="text-xs">
            {(path.total_probability * 100).toFixed(1)}% prob
          </Badge>
          <Badge variant="outline" className="text-xs">
            Complexity: {path.complexity_score.toFixed(1)}
          </Badge>
        </div>
      </div>
    </div>
  );
}