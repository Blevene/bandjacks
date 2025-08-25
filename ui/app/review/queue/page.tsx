"use client";

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/page-header";
import { LoadingSpinner } from "@/components/shared/loading-spinner";
import { typedApi } from "@/lib/api-client";
import type { UncertaintyQueueItem, QueueStatistics } from "@/lib/simulation-types";
import { ReviewItem } from "@/components/review/review-item";
import { QueueStats } from "@/components/review/queue-stats";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw, Filter, Brain } from "lucide-react";

const itemTypeLabels = {
  flow_edge: "Flow Edge",
  mapping: "Technique Mapping",
  extraction: "Entity Extraction",
  detection: "Detection Strategy",
};

export default function ReviewQueuePage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState<UncertaintyQueueItem[]>([]);
  const [statistics, setStatistics] = useState<QueueStatistics | null>(null);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.7);
  const [error, setError] = useState<string | null>(null);

  const fetchQueueItems = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const [itemsResponse, statsResponse] = await Promise.all([
        typedApi.activeLearning.getQueue({
          item_type: selectedType || undefined,
          confidence_threshold: confidenceThreshold,
          limit: 50,
        }),
        typedApi.activeLearning.getStatistics(),
      ]);
      
      setItems(itemsResponse);
      setStatistics(statsResponse);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to fetch queue items");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueueItems();
  }, [selectedType, confidenceThreshold]);

  const handleReviewDecision = async (
    queueId: string,
    decision: "accept" | "edit" | "reject",
    notes?: string,
    updatedValue?: any
  ) => {
    try {
      await typedApi.activeLearning.reviewItem({
        queue_id: queueId,
        decision,
        reviewed_by: "current_user", // In production, get from auth context
        notes,
        updated_value: updatedValue,
      });
      
      // Remove item from list
      setItems(items.filter(item => item.queue_id !== queueId));
      
      // Update statistics
      if (statistics) {
        setStatistics({
          ...statistics,
          total: statistics.total - 1,
          by_status: {
            ...statistics.by_status,
            pending: (statistics.by_status.pending || 0) - 1,
            reviewed: (statistics.by_status.reviewed || 0) + 1,
          },
        });
      }
    } catch (err: any) {
      console.error("Review failed:", err);
    }
  };

  return (
    <div className="container mx-auto p-6">
      <PageHeader
        title="Active Learning Review Queue"
        description="Review uncertain items to improve system confidence and accuracy"
      />

      {/* Statistics */}
      {statistics && (
        <div className="mt-6">
          <QueueStats statistics={statistics} />
        </div>
      )}

      {/* Filters */}
      <Card className="mt-6 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Filter by Type:</span>
              <div className="flex gap-2">
                <Button
                  variant={selectedType === null ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSelectedType(null)}
                >
                  All
                </Button>
                {Object.entries(itemTypeLabels).map(([type, label]) => (
                  <Button
                    key={type}
                    variant={selectedType === type ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSelectedType(type)}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Max Confidence:</span>
              <select
                className="px-2 py-1 border rounded-md text-sm"
                value={confidenceThreshold}
                onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
              >
                <option value={0.5}>50%</option>
                <option value={0.6}>60%</option>
                <option value={0.7}>70%</option>
                <option value={0.8}>80%</option>
                <option value={0.9}>90%</option>
              </select>
            </div>
          </div>
          
          <Button onClick={fetchQueueItems} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </Card>

      {/* Queue Items */}
      <Card className="mt-6 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">
            Pending Review Items ({items.length})
          </h3>
          {items.length > 0 && (
            <Badge variant="secondary">
              <Brain className="h-3 w-3 mr-1" />
              Avg Confidence: {
                (items.reduce((sum, item) => sum + item.confidence, 0) / items.length * 100).toFixed(0)
              }%
            </Badge>
          )}
        </div>

        {loading ? (
          <div className="flex justify-center py-8">
            <LoadingSpinner />
          </div>
        ) : error ? (
          <div className="text-center py-8 text-red-600">{error}</div>
        ) : items.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            No items pending review with current filters
          </div>
        ) : (
          <div className="space-y-4">
            {items.map((item) => (
              <ReviewItem
                key={item.queue_id}
                item={item}
                onDecision={handleReviewDecision}
              />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}