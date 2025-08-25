"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingSpinner } from "@/components/shared/loading-spinner";
import { typedApi } from "@/lib/api-client";
import type { PathPrediction, PathPredictionRequest } from "@/lib/simulation-types";
import { TrendingUp, Users, Plus, X, Brain } from "lucide-react";

export function PredictionPanel() {
  const [loading, setLoading] = useState(false);
  const [predictions, setPredictions] = useState<PathPrediction[]>([]);
  const [confidence, setConfidence] = useState<number>(0);
  const [analysis, setAnalysis] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  
  const [currentTechniques, setCurrentTechniques] = useState<string[]>([]);
  const [newTechnique, setNewTechnique] = useState("");
  const [threatGroup, setThreatGroup] = useState("");
  const [maxPredictions, setMaxPredictions] = useState(5);
  const [includeRationale, setIncludeRationale] = useState(true);

  const addTechnique = () => {
    if (newTechnique && !currentTechniques.includes(newTechnique)) {
      setCurrentTechniques([...currentTechniques, newTechnique]);
      setNewTechnique("");
    }
  };

  const removeTechnique = (tech: string) => {
    setCurrentTechniques(currentTechniques.filter(t => t !== tech));
  };

  const handlePredict = async () => {
    if (currentTechniques.length === 0) {
      setError("Please add at least one current technique");
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      const request: PathPredictionRequest = {
        current_techniques: currentTechniques,
        threat_group: threatGroup || undefined,
        max_predictions: maxPredictions,
        include_rationale: includeRationale,
      };
      
      const response = await typedApi.simulation.predict(request);
      setPredictions(response.predictions);
      setConfidence(response.confidence);
      setAnalysis(response.analysis || "");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Prediction failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Current Attack State</h3>
        
        <div className="space-y-4">
          {/* Current Techniques */}
          <div>
            <label className="block text-sm font-medium mb-2">
              Current Technique Sequence
            </label>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                className="flex-1 px-3 py-2 border rounded-md"
                placeholder="e.g., T1055"
                value={newTechnique}
                onChange={(e) => setNewTechnique(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && addTechnique()}
              />
              <Button onClick={addTechnique} size="sm">
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            
            {currentTechniques.length > 0 && (
              <div className="flex flex-wrap gap-2 p-3 bg-muted/50 rounded-md">
                {currentTechniques.map((tech, idx) => (
                  <Badge key={idx} variant="secondary" className="pl-3 pr-1 py-1">
                    <span className="mr-1 text-xs text-muted-foreground">
                      {idx + 1}.
                    </span>
                    {tech}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="ml-1 h-4 w-4 p-0"
                      onClick={() => removeTechnique(tech)}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Threat Group Context */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Threat Group Context (Optional)
              </label>
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  className="flex-1 px-3 py-2 border rounded-md"
                  placeholder="e.g., G0001"
                  value={threatGroup}
                  onChange={(e) => setThreatGroup(e.target.value)}
                />
              </div>
            </div>

            {/* Max Predictions */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Max Predictions
              </label>
              <input
                type="number"
                className="w-full px-3 py-2 border rounded-md"
                min={1}
                max={20}
                value={maxPredictions}
                onChange={(e) => setMaxPredictions(parseInt(e.target.value))}
              />
            </div>
          </div>

          {/* Include Rationale */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="include-rationale"
              className="mr-2"
              checked={includeRationale}
              onChange={(e) => setIncludeRationale(e.target.checked)}
            />
            <label htmlFor="include-rationale" className="text-sm font-medium">
              Include prediction rationale
            </label>
          </div>
        </div>

        <Button
          onClick={handlePredict}
          disabled={loading || currentTechniques.length === 0}
          className="mt-4"
        >
          {loading ? (
            <>
              <LoadingSpinner className="mr-2" />
              Predicting...
            </>
          ) : (
            <>
              <Brain className="h-4 w-4 mr-2" />
              Predict Next Steps
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
      {predictions.length > 0 && (
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Predicted Next Steps</h3>
            <Badge variant={confidence > 0.7 ? "default" : "secondary"}>
              {(confidence * 100).toFixed(0)}% confidence
            </Badge>
          </div>

          {analysis && (
            <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-md">
              <p className="text-sm text-blue-800">{analysis}</p>
            </div>
          )}
          
          <div className="space-y-3">
            {predictions.map((pred, idx) => (
              <PredictionCard key={idx} prediction={pred} rank={idx + 1} />
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function PredictionCard({ 
  prediction, 
  rank 
}: { 
  prediction: PathPrediction; 
  rank: number;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
              <span className="text-sm font-semibold">{rank}</span>
            </div>
            <div>
              <span className="font-medium">{prediction.technique_id}</span>
              <span className="text-sm text-muted-foreground ml-2">
                {prediction.technique_name}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 ml-11">
            <Badge variant="outline">{prediction.tactic}</Badge>
            <Badge variant="secondary">
              <TrendingUp className="h-3 w-3 mr-1" />
              {(prediction.probability * 100).toFixed(1)}%
            </Badge>
            {prediction.historical_frequency !== undefined && (
              <span className="text-xs text-muted-foreground">
                Historical frequency: {(prediction.historical_frequency * 100).toFixed(0)}%
              </span>
            )}
          </div>

          {prediction.rationale && (
            <p className="text-sm text-muted-foreground mt-2 ml-11">
              {prediction.rationale}
            </p>
          )}
        </div>
      </div>
    </Card>
  );
}