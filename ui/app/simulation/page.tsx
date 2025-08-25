"use client";

import { useState } from "react";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { TabsNavigation } from "@/components/shared/tabs-navigation";
import { PathSimulator } from "@/components/simulation/path-simulator";
import { PredictionPanel } from "@/components/simulation/prediction-panel";
import { WhatIfAnalyzer } from "@/components/simulation/whatif-analyzer";
import { ScenarioBuilder } from "@/components/simulation/scenario-builder";

const tabs = [
  { id: "paths", label: "Path Simulation" },
  { id: "predict", label: "Prediction" },
  { id: "whatif", label: "What-If Analysis" },
  { id: "scenario", label: "Scenario Builder" },
];

export default function SimulationPage() {
  const [activeTab, setActiveTab] = useState("paths");

  return (
    <div className="container mx-auto p-6">
      <PageHeader
        title="Attack Simulation"
        description="Simulate attack paths, predict next steps, and analyze defensive scenarios"
      />

      <Card className="mt-6">
        <TabsNavigation
          tabs={tabs}
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        <div className="p-6">
          {activeTab === "paths" && <PathSimulator />}
          {activeTab === "predict" && <PredictionPanel />}
          {activeTab === "whatif" && <WhatIfAnalyzer />}
          {activeTab === "scenario" && <ScenarioBuilder />}
        </div>
      </Card>
    </div>
  );
}