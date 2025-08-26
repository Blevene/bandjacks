"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Brain, TrendingUp } from "lucide-react";

export function PredictionPanel() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            Technique Prediction
          </CardTitle>
          <CardDescription>
            Predict the next likely techniques based on current attack state
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            <div className="text-center">
              <TrendingUp className="h-8 w-8 mx-auto mb-2" />
              <p>Prediction functionality coming soon</p>
              <p className="text-xs">This will predict next attack steps based on current state</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}