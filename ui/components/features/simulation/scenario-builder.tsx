"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Layers, Settings } from "lucide-react";

export function ScenarioBuilder() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5" />
            Scenario Builder
          </CardTitle>
          <CardDescription>
            Build complex attack scenarios with multiple phases and objectives
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            <div className="text-center">
              <Settings className="h-8 w-8 mx-auto mb-2" />
              <p>Scenario builder functionality coming soon</p>
              <p className="text-xs">This will help create multi-stage attack scenarios</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}