"use client";

import { Progress } from "@/components/ui/progress";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  CheckCircle,
  XCircle,
  Edit,
  Clock,
  Shield,
  GitBranch,
  Users,
  Bug,
  Target,
} from "lucide-react";
import type { ReviewableItem } from "@/lib/report-types";
import { calculateReviewProgress } from "@/lib/review-utils";

interface ReviewProgressProps {
  items: ReviewableItem[];
  className?: string;
}

export function ReviewProgress({ items, className }: ReviewProgressProps) {
  const stats = calculateReviewProgress(items);
  
  const getIcon = (type: string) => {
    switch (type) {
      case 'entities':
        return <Users className="h-4 w-4" />;
      case 'techniques':
        return <Shield className="h-4 w-4" />;
      case 'flowSteps':
        return <GitBranch className="h-4 w-4" />;
      default:
        return <Clock className="h-4 w-4" />;
    }
  };
  
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="text-lg">Review Progress</CardTitle>
        <CardDescription>
          {stats.reviewed} of {stats.total} items reviewed
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Overall progress bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Overall Progress</span>
            <span className="font-medium">{Math.round(stats.progress)}%</span>
          </div>
          <Progress value={stats.progress} className="h-2" />
        </div>
        
        {/* Status breakdown */}
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-500" />
            <div className="flex-1">
              <p className="text-sm font-medium">{stats.approved}</p>
              <p className="text-xs text-muted-foreground">Approved</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <XCircle className="h-4 w-4 text-red-500" />
            <div className="flex-1">
              <p className="text-sm font-medium">{stats.rejected}</p>
              <p className="text-xs text-muted-foreground">Rejected</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Edit className="h-4 w-4 text-blue-500" />
            <div className="flex-1">
              <p className="text-sm font-medium">{stats.edited}</p>
              <p className="text-xs text-muted-foreground">Edited</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-gray-500" />
            <div className="flex-1">
              <p className="text-sm font-medium">{stats.pending}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
          </div>
        </div>
        
        {/* Progress by type */}
        <div className="space-y-3 pt-2 border-t">
          <p className="text-sm font-medium">Progress by Type</p>
          {Object.entries(stats.byType).map(([type, count]) => {
            const reviewed = stats.reviewedByType[type as keyof typeof stats.reviewedByType];
            const progress = count > 0 ? (reviewed / count) * 100 : 0;
            
            return (
              <div key={type} className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    {getIcon(type)}
                    <span className="capitalize">
                      {type.replace(/([A-Z])/g, ' $1').trim()}
                    </span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {reviewed}/{count}
                  </span>
                </div>
                <Progress value={progress} className="h-1.5" />
              </div>
            );
          })}
        </div>
        
        {/* Completion status */}
        {stats.progress === 100 && (
          <div className="pt-2 border-t">
            <Badge variant="default" className="w-full justify-center">
              <CheckCircle className="h-3 w-3 mr-1" />
              Review Complete
            </Badge>
          </div>
        )}
      </CardContent>
    </Card>
  );
}