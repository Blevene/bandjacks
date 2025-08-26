"use client";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { PathSimulator } from "@/components/features/simulation/path-simulator";
import { PredictionPanel } from "@/components/features/simulation/prediction-panel";
import { WhatIfAnalyzer } from "@/components/features/simulation/whatif-analyzer";
import { ScenarioBuilder } from "@/components/features/simulation/scenario-builder";
import { GitBranch, Brain, Shield, Layers } from "lucide-react";

export default function SimulationPage() {
  return (
    <div className="container mx-auto p-6">
      <PageHeader
        title="Attack Simulation"
        description="Simulate attack paths, predict next steps, and analyze defensive scenarios"
      />

      <Tabs defaultValue="paths" className="mt-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="paths">
            <GitBranch className="h-4 w-4 mr-2" />
            Path Simulation
          </TabsTrigger>
          <TabsTrigger value="predict">
            <Brain className="h-4 w-4 mr-2" />
            Prediction
          </TabsTrigger>
          <TabsTrigger value="whatif">
            <Shield className="h-4 w-4 mr-2" />
            What-If Analysis
          </TabsTrigger>
          <TabsTrigger value="scenario">
            <Layers className="h-4 w-4 mr-2" />
            Scenario Builder
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="paths">
          <PathSimulator />
        </TabsContent>
        
        <TabsContent value="predict">
          <PredictionPanel />
        </TabsContent>
        
        <TabsContent value="whatif">
          <WhatIfAnalyzer />
        </TabsContent>
        
        <TabsContent value="scenario">
          <ScenarioBuilder />
        </TabsContent>
      </Tabs>
    </div>
  );
}