import React from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  CheckCircle2,
  Database,
  GitBranch,
  Link,
  RefreshCw,
  AlertTriangle,
  TrendingUp,
} from 'lucide-react';

interface GraphStats {
  entities: {
    created: number;
    updated: number;
  };
  techniques: {
    created: number;
    updated: number;
    skipped?: number;
  };
  total_nodes_created: number;
  total_nodes_updated: number;
  total_edges_created: number;
  total_edges_updated: number;
  duplicates_consolidated: number;
}

interface GraphConfirmationDialogProps {
  open: boolean;
  onClose: () => void;
  stats?: GraphStats;
  message?: string;
  onViewReport?: () => void;
}

export function GraphConfirmationDialog({
  open,
  onClose,
  stats,
  message,
  onViewReport,
}: GraphConfirmationDialogProps) {
  const hasChanges = stats && (
    stats.total_nodes_created > 0 ||
    stats.total_nodes_updated > 0 ||
    stats.total_edges_created > 0 ||
    stats.total_edges_updated > 0
  );

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-600" />
            Graph Successfully Updated
          </DialogTitle>
          <DialogDescription>
            {message || "Your review decisions have been applied to the Neo4j knowledge graph"}
          </DialogDescription>
        </DialogHeader>

        {stats && (
          <div className="space-y-4">
            {/* Summary Statistics */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-blue-500" />
                  <span className="font-semibold">Entities</span>
                </div>
                <div className="space-y-1 pl-6">
                  {stats.entities.created > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Created:</span>
                      <Badge variant="default" className="bg-green-600">
                        {stats.entities.created}
                      </Badge>
                    </div>
                  )}
                  {stats.entities.updated > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Updated:</span>
                      <Badge variant="secondary">
                        {stats.entities.updated}
                      </Badge>
                    </div>
                  )}
                  {stats.entities.created === 0 && stats.entities.updated === 0 && (
                    <span className="text-sm text-muted-foreground">No changes</span>
                  )}
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <GitBranch className="h-4 w-4 text-purple-500" />
                  <span className="font-semibold">Techniques</span>
                </div>
                <div className="space-y-1 pl-6">
                  {stats.techniques.created > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Linked:</span>
                      <Badge variant="default" className="bg-green-600">
                        {stats.techniques.created}
                      </Badge>
                    </div>
                  )}
                  {stats.techniques.updated > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Updated:</span>
                      <Badge variant="secondary">
                        {stats.techniques.updated}
                      </Badge>
                    </div>
                  )}
                  {stats.techniques.created === 0 && stats.techniques.updated === 0 && (
                    <span className="text-sm text-muted-foreground">No changes</span>
                  )}
                </div>
              </div>
            </div>

            {/* Consolidation Alert */}
            {stats.duplicates_consolidated > 0 && (
              <Alert>
                <RefreshCw className="h-4 w-4" />
                <AlertDescription>
                  {stats.duplicates_consolidated} duplicate relationships were consolidated to maintain graph integrity.
                </AlertDescription>
              </Alert>
            )}

            {/* Overall Summary */}
            <div className="border-t pt-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold">Total Graph Changes:</span>
                <div className="flex gap-2">
                  {stats.total_nodes_created > 0 && (
                    <Badge variant="default" className="bg-blue-600">
                      <Database className="h-3 w-3 mr-1" />
                      {stats.total_nodes_created} nodes
                    </Badge>
                  )}
                  {stats.total_edges_created > 0 && (
                    <Badge variant="default" className="bg-purple-600">
                      <Link className="h-3 w-3 mr-1" />
                      {stats.total_edges_created} edges
                    </Badge>
                  )}
                  {stats.total_nodes_updated + stats.total_edges_updated > 0 && (
                    <Badge variant="secondary">
                      <RefreshCw className="h-3 w-3 mr-1" />
                      {stats.total_nodes_updated + stats.total_edges_updated} updates
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            {/* No Changes Alert */}
            {!hasChanges && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  No new changes were made to the graph. All approved items were already present.
                </AlertDescription>
              </Alert>
            )}

            {/* Success Alert */}
            {hasChanges && (
              <Alert className="border-green-200 bg-green-50">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <AlertDescription className="text-green-800">
                  The knowledge graph has been successfully enriched with your approved intelligence.
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        <DialogFooter>
          {onViewReport && (
            <Button variant="outline" onClick={onViewReport}>
              View Report
            </Button>
          )}
          <Button onClick={onClose}>
            <CheckCircle2 className="h-4 w-4 mr-2" />
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}