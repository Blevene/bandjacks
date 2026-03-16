import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '@/lib/config';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Network,
  GitBranch,
  Database,
  ArrowRight,
  Loader2,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Eye,
} from 'lucide-react';

interface GraphNode {
  id: string;
  label: string;
  properties: Record<string, any>;
  action: 'create' | 'update' | 'link';
}

interface GraphEdge {
  source_id: string;
  target_id: string;
  relationship_type: string;
  properties: Record<string, any>;
  action: 'create' | 'update';
}

interface GraphSimulation {
  success: boolean;
  message: string;
  summary: Record<string, number>;
  nodes: GraphNode[];
  edges: GraphEdge[];
  attack_chains?: Array<{
    chain_id: string;
    techniques: string[];
    description: string;
  }>;
}

interface GraphPreviewModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  reportId: string;
  decisions: any[];
  globalNotes: string;
  loading?: boolean;
}

export function GraphPreviewModal({
  open,
  onClose,
  onConfirm,
  reportId,
  decisions,
  globalNotes,
  loading = false,
}: GraphPreviewModalProps) {
  const [simulation, setSimulation] = useState<GraphSimulation | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open && reportId && decisions.length > 0) {
      fetchSimulation();
    }
  }, [open, reportId, decisions]);

  const fetchSimulation = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_BASE_URL}/v1/reports/${reportId}/graph-simulation`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            report_id: reportId,
            reviewer_id: 'current-user',
            decisions,
            global_notes: globalNotes,
            review_timestamp: new Date().toISOString(),
          }),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch graph simulation');
      }

      const data = await response.json();
      setSimulation(data);
    } catch (err: any) {
      setError(err.message || 'Failed to simulate graph changes');
    } finally {
      setIsLoading(false);
    }
  };

  const getNodeIcon = (label: string) => {
    switch (label) {
      case 'Report':
        return <Database className="h-4 w-4" />;
      case 'AttackEpisode':
        return <GitBranch className="h-4 w-4" />;
      case 'AttackPattern':
      case 'AttackAction':
        return <Network className="h-4 w-4" />;
      default:
        return null;
    }
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'create':
        return (
          <Badge variant="default" className="bg-green-600">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Create
          </Badge>
        );
      case 'update':
        return (
          <Badge variant="secondary">
            <Eye className="h-3 w-3 mr-1" />
            Update
          </Badge>
        );
      case 'link':
        return (
          <Badge variant="outline">
            <ArrowRight className="h-3 w-3 mr-1" />
            Link
          </Badge>
        );
      default:
        return null;
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Graph Preview - Dry Run
          </DialogTitle>
          <DialogDescription>
            Preview the Neo4j graph changes that will be created from your review decisions
          </DialogDescription>
        </DialogHeader>

        {isLoading && (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {simulation && !isLoading && (
          <Tabs defaultValue="summary" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="summary">Summary</TabsTrigger>
              <TabsTrigger value="nodes">
                Nodes ({simulation.nodes.length})
              </TabsTrigger>
              <TabsTrigger value="edges">
                Edges ({simulation.edges.length})
              </TabsTrigger>
              <TabsTrigger value="chains">Attack Chains</TabsTrigger>
            </TabsList>

            <TabsContent value="summary" className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <h3 className="font-semibold">Nodes</h3>
                  <div className="space-y-1 text-sm">
                    <div className="flex justify-between">
                      <span>To Create:</span>
                      <Badge variant="default">
                        {simulation.summary.nodes_to_create || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>To Update:</span>
                      <Badge variant="secondary">
                        {simulation.summary.nodes_to_update || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>To Link:</span>
                      <Badge variant="outline">
                        {simulation.summary.nodes_to_link || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between font-semibold pt-2 border-t">
                      <span>Total Nodes:</span>
                      <span>{simulation.summary.total_nodes || 0}</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h3 className="font-semibold">Review Statistics</h3>
                  <div className="space-y-1 text-sm">
                    <div className="flex justify-between">
                      <span>Approved Entities:</span>
                      <Badge variant="default" className="bg-green-600">
                        {simulation.summary.approved_entities || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Approved Techniques:</span>
                      <Badge variant="default" className="bg-green-600">
                        {simulation.summary.approved_techniques || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Approved Flow Steps:</span>
                      <Badge variant="default" className="bg-green-600">
                        {simulation.summary.approved_flow_steps || 0}
                      </Badge>
                    </div>
                    <div className="flex justify-between font-semibold pt-2 border-t">
                      <span>Total Edges:</span>
                      <span>{simulation.summary.total_edges || 0}</span>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="nodes">
              <ScrollArea className="h-[400px] w-full">
                <div className="space-y-2">
                  {simulation.nodes.map((node, idx) => (
                    <div
                      key={idx}
                      className="flex items-start justify-between p-3 border rounded-lg"
                    >
                      <div className="flex items-start gap-3">
                        {getNodeIcon(node.label)}
                        <div className="space-y-1">
                          <div className="font-medium">{node.label}</div>
                          <div className="text-sm text-muted-foreground">
                            {node.properties.name || node.id}
                          </div>
                          {node.properties.confidence && (
                            <Badge variant="secondary" className="text-xs">
                              {node.properties.confidence}% confidence
                            </Badge>
                          )}
                        </div>
                      </div>
                      {getActionBadge(node.action)}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="edges">
              <ScrollArea className="h-[400px] w-full">
                <div className="space-y-2">
                  {simulation.edges.map((edge, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 border rounded-lg"
                    >
                      <div className="flex items-center gap-2 text-sm">
                        <code className="px-2 py-1 bg-muted rounded">
                          {edge.source_id.split('--')[0]}
                        </code>
                        <ArrowRight className="h-4 w-4" />
                        <Badge variant="outline">{edge.relationship_type}</Badge>
                        <ArrowRight className="h-4 w-4" />
                        <code className="px-2 py-1 bg-muted rounded">
                          {edge.target_id.split('--')[0]}
                        </code>
                      </div>
                      {edge.properties.probability && (
                        <Badge variant="secondary" className="text-xs">
                          {(edge.properties.probability * 100).toFixed(0)}%
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="chains">
              {simulation.attack_chains && simulation.attack_chains.length > 0 ? (
                <ScrollArea className="h-[400px] w-full">
                  <div className="space-y-4">
                    {simulation.attack_chains.map((chain, idx) => (
                      <div key={idx} className="p-4 border rounded-lg space-y-3">
                        <div className="font-medium">{chain.description}</div>
                        <div className="flex flex-wrap gap-2">
                          {chain.techniques.map((technique, tIdx) => (
                            <React.Fragment key={tIdx}>
                              <Badge variant="secondary">{technique}</Badge>
                              {tIdx < chain.techniques.length - 1 && (
                                <ArrowRight className="h-4 w-4 text-muted-foreground" />
                              )}
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  No attack chains detected in this review
                </div>
              )}
            </TabsContent>
          </Tabs>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Submitting...
              </>
            ) : (
              'Confirm & Submit'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}