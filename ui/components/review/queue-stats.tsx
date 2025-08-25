"use client";

import { Card } from "@/components/ui/card";
import type { QueueStatistics } from "@/lib/simulation-types";
import { Brain, CheckCircle, Clock, AlertTriangle } from "lucide-react";

interface QueueStatsProps {
  statistics: QueueStatistics;
}

export function QueueStats({ statistics }: QueueStatsProps) {
  const pendingCount = statistics.by_status.pending || 0;
  const reviewedCount = statistics.by_status.reviewed || 0;
  const rejectedCount = statistics.by_status.rejected || 0;

  return (
    <div className="grid grid-cols-4 gap-4">
      {/* Total Items */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Total Items</p>
            <p className="text-2xl font-bold">{statistics.total}</p>
          </div>
          <Brain className="h-8 w-8 text-muted-foreground" />
        </div>
      </Card>

      {/* Pending Review */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Pending Review</p>
            <p className="text-2xl font-bold text-orange-600">{pendingCount}</p>
          </div>
          <Clock className="h-8 w-8 text-orange-600" />
        </div>
      </Card>

      {/* Reviewed */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Reviewed</p>
            <p className="text-2xl font-bold text-green-600">{reviewedCount}</p>
          </div>
          <CheckCircle className="h-8 w-8 text-green-600" />
        </div>
      </Card>

      {/* Average Confidence */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">Avg Confidence</p>
            <p className="text-2xl font-bold">
              {statistics.confidence_stats 
                ? `${(statistics.confidence_stats.average * 100).toFixed(0)}%`
                : "N/A"}
            </p>
            {statistics.confidence_stats && (
              <p className="text-xs text-muted-foreground mt-1">
                Range: {(statistics.confidence_stats.min * 100).toFixed(0)}% - 
                {(statistics.confidence_stats.max * 100).toFixed(0)}%
              </p>
            )}
          </div>
          <AlertTriangle className="h-8 w-8 text-muted-foreground" />
        </div>
      </Card>

      {/* By Type Breakdown */}
      {Object.keys(statistics.by_type).length > 0 && (
        <Card className="p-4 col-span-4">
          <h4 className="text-sm font-medium mb-3">Items by Type</h4>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(statistics.by_type).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                <span className="text-sm capitalize">{type.replace("_", " ")}</span>
                <span className="font-semibold">{count}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}