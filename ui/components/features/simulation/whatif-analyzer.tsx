"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertTriangle } from "lucide-react";

export function WhatIfAnalyzer() {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            What-If Analysis
          </CardTitle>
          <CardDescription>
            Analyze how defensive measures would impact attack paths
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            <div className="text-center">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
              <p>What-if analysis functionality coming soon</p>
              <p className="text-xs">This will show how defenses affect attack success rates</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}