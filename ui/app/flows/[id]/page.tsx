"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams } from "next/navigation";
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  MarkerType,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  AlertTriangle,
  GitBranch,
  Loader2,
  ChevronRight,
  Activity,
  Target,
  Layers,
  Info,
  Eye,
  EyeOff,
  Download,
  Share2,
  Settings,
  Play
} from "lucide-react";
import Link from "next/link";

// Custom node component for techniques
const TechniqueNode = ({ data }: { data: any }) => {
  return (
    <div className="px-4 py-2 shadow-md rounded-md bg-white border-2 border-stone-400">
      <div className="flex items-center gap-2">
        <Target className="h-4 w-4 text-red-500" />
        <div>
          <div className="text-sm font-bold">{data.label}</div>
          {data.external_id && (
            <div className="text-xs text-gray-500">{data.external_id}</div>
          )}
        </div>
      </div>
    </div>
  );
};

// Custom node component for conditions
const ConditionNode = ({ data }: { data: any }) => {
  return (
    <div className="px-3 py-2 shadow-md rounded-full bg-yellow-50 border-2 border-yellow-400">
      <div className="flex items-center gap-2">
        <GitBranch className="h-4 w-4 text-yellow-600" />
        <div className="text-sm">{data.label}</div>
      </div>
    </div>
  );
};

// Custom node component for D3FEND defenses
const DefenseNode = ({ data }: { data: any }) => {
  return (
    <div className="px-4 py-2 shadow-md rounded-md bg-green-50 border-2 border-green-400">
      <div className="flex items-center gap-2">
        <Shield className="h-4 w-4 text-green-600" />
        <div>
          <div className="text-sm font-bold">{data.label}</div>
          <div className="text-xs text-gray-500">D3FEND</div>
        </div>
      </div>
    </div>
  );
};

const nodeTypes = {
  technique: TechniqueNode,
  condition: ConditionNode,
  defense: DefenseNode,
};

export default function FlowDetailPage() {
  const params = useParams();
  const flowId = params.id as string;
  const [flow, setFlow] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showDefenses, setShowDefenses] = useState(false);
  const [defenseOverlay, setDefenseOverlay] = useState<any>(null);
  const { toast } = useToast();

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    if (flowId) {
      fetchFlow();
    }
  }, [flowId]);

  const fetchFlow = async () => {
    try {
      // Try to get the flow
      const response = await fetch(`http://localhost:8001/v1/attackflow/${encodeURIComponent(flowId)}`);
      
      if (response.ok) {
        const data = await response.json();
        setFlow(data);
        
        // Convert flow to ReactFlow nodes and edges
        const flowNodes = convertToReactFlowNodes(data);
        const flowEdges = convertToReactFlowEdges(data);
        
        setNodes(flowNodes);
        setEdges(flowEdges);
        
        // Fetch defense overlay if available
        fetchDefenseOverlay();
      } else {
        // Try rendering endpoint
        const renderResponse = await fetch(`http://localhost:8001/v1/attackflow/render/${encodeURIComponent(flowId)}`);
        if (renderResponse.ok) {
          const renderData = await renderResponse.json();
          setFlow(renderData);
          
          const flowNodes = convertToReactFlowNodes(renderData);
          const flowEdges = convertToReactFlowEdges(renderData);
          
          setNodes(flowNodes);
          setEdges(flowEdges);
        }
      }
    } catch (error: any) {
      console.error("Error fetching flow:", error);
      toast({
        title: "Error loading flow",
        description: "Failed to load attack flow details",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchDefenseOverlay = async () => {
    try {
      const response = await fetch(`http://localhost:8001/v1/defense/overlay/${encodeURIComponent(flowId)}`);
      if (response.ok) {
        const data = await response.json();
        setDefenseOverlay(data);
      }
    } catch (error) {
      console.error("Error fetching defense overlay:", error);
    }
  };

  const convertToReactFlowNodes = (flowData: any): Node[] => {
    const nodes: Node[] = [];
    let yPos = 0;
    
    // Create nodes for actions
    if (flowData.actions) {
      flowData.actions.forEach((action: any, index: number) => {
        nodes.push({
          id: action.id || `action-${index}`,
          type: "technique",
          position: { x: 250, y: yPos },
          data: {
            label: action.name || `Action ${index + 1}`,
            external_id: action.technique_id,
            ...action
          },
        });
        yPos += 100;
      });
    }
    
    // Create nodes for conditions
    if (flowData.conditions) {
      flowData.conditions.forEach((condition: any, index: number) => {
        nodes.push({
          id: condition.id || `condition-${index}`,
          type: "condition",
          position: { x: 500, y: 50 + index * 150 },
          data: {
            label: condition.name || condition.expression || "Condition",
            ...condition
          },
        });
      });
    }
    
    return nodes;
  };

  const convertToReactFlowEdges = (flowData: any): Edge[] => {
    const edges: Edge[] = [];
    
    // Create edges for flow sequence
    if (flowData.sequence) {
      flowData.sequence.forEach((seq: any, index: number) => {
        edges.push({
          id: `edge-${index}`,
          source: seq.from,
          target: seq.to,
          type: "smoothstep",
          animated: true,
          markerEnd: {
            type: MarkerType.ArrowClosed,
          },
          label: seq.probability ? `${(seq.probability * 100).toFixed(0)}%` : undefined,
        });
      });
    }
    
    // Create edges between actions if they're sequential
    if (flowData.actions && flowData.actions.length > 1) {
      for (let i = 0; i < flowData.actions.length - 1; i++) {
        const sourceId = flowData.actions[i].id || `action-${i}`;
        const targetId = flowData.actions[i + 1].id || `action-${i + 1}`;
        
        // Check if edge already exists
        if (!edges.some(e => e.source === sourceId && e.target === targetId)) {
          edges.push({
            id: `edge-seq-${i}`,
            source: sourceId,
            target: targetId,
            type: "smoothstep",
            animated: true,
            markerEnd: {
              type: MarkerType.ArrowClosed,
            },
          });
        }
      }
    }
    
    return edges;
  };

  const toggleDefenseOverlay = () => {
    if (!showDefenses && defenseOverlay) {
      // Add defense nodes
      const defenseNodes: Node[] = [];
      const currentNodes = [...nodes];
      
      defenseOverlay.defenses?.forEach((defense: any, index: number) => {
        const techniqueNode = currentNodes.find(n => 
          n.data.technique_id === defense.technique_id
        );
        
        if (techniqueNode) {
          defenseNodes.push({
            id: `defense-${index}`,
            type: "defense",
            position: {
              x: techniqueNode.position.x + 200,
              y: techniqueNode.position.y
            },
            data: {
              label: defense.name,
              ...defense
            },
          });
        }
      });
      
      setNodes([...currentNodes, ...defenseNodes]);
    } else {
      // Remove defense nodes
      setNodes(nodes.filter(n => n.type !== "defense"));
    }
    
    setShowDefenses(!showDefenses);
  };

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!flow) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <p className="text-lg font-medium">Flow not found</p>
          <p className="text-sm text-muted-foreground mt-2">
            The attack flow "{flowId}" could not be found.
          </p>
          <Link href="/flows">
            <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              Back to Flows
            </button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link href="/flows" className="text-muted-foreground hover:text-foreground">
              Flows
            </Link>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
            <span>{flow.name || flowId}</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">{flow.name || "Attack Flow"}</h1>
          {flow.description && (
            <p className="text-muted-foreground mt-2">{flow.description}</p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={toggleDefenseOverlay}
            className={`flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted ${
              showDefenses ? "bg-green-50 border-green-500" : ""
            }`}
          >
            {showDefenses ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            D3FEND Overlay
          </button>
          <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
            <Play className="h-4 w-4" />
            Simulate
          </button>
          <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
            <Download className="h-4 w-4" />
            Export
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Actions</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{flow.action_count || nodes.filter(n => n.type === "technique").length}</div>
            <p className="text-xs text-muted-foreground">
              Attack steps
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Conditions</CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{flow.condition_count || nodes.filter(n => n.type === "condition").length}</div>
            <p className="text-xs text-muted-foreground">
              Decision points
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coverage</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {defenseOverlay?.coverage_percentage?.toFixed(0) || 0}%
            </div>
            <p className="text-xs text-muted-foreground">
              Defense coverage
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Complexity</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {flow.complexity || "Medium"}
            </div>
            <p className="text-xs text-muted-foreground">
              Flow complexity
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <CardHeader>
          <CardTitle>Flow Visualization</CardTitle>
          <CardDescription>
            Interactive graph showing the attack sequence
            {showDefenses && " with D3FEND defensive countermeasures"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div style={{ width: "100%", height: "600px" }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              nodeTypes={nodeTypes}
              fitView
            >
              <Background variant="dots" gap={12} size={1} />
              <Controls />
              <MiniMap />
            </ReactFlow>
          </div>
        </CardContent>
      </Card>

      {flow.metadata && (
        <Card>
          <CardHeader>
            <CardTitle>Flow Metadata</CardTitle>
            <CardDescription>Additional information about this flow</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <p className="text-sm font-medium">Author</p>
                <p className="text-sm text-muted-foreground">{flow.metadata.author || "Unknown"}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Created</p>
                <p className="text-sm text-muted-foreground">{flow.created || "Unknown"}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Scope</p>
                <p className="text-sm text-muted-foreground">{flow.scope || "General"}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Confidence</p>
                <p className="text-sm text-muted-foreground">
                  {flow.confidence ? `${(flow.confidence * 100).toFixed(0)}%` : "Not specified"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {defenseOverlay && defenseOverlay.recommendations && (
        <Card>
          <CardHeader>
            <CardTitle>Defense Recommendations</CardTitle>
            <CardDescription>
              Suggested countermeasures based on minimal cut analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {defenseOverlay.recommendations.map((rec: any, index: number) => (
                <div key={index} className="flex items-start gap-3 p-3 border rounded-md">
                  <Shield className="h-5 w-5 text-green-500 mt-0.5" />
                  <div className="flex-1">
                    <p className="font-medium">{rec.name}</p>
                    <p className="text-sm text-muted-foreground mt-1">{rec.description}</p>
                    {rec.techniques && (
                      <div className="flex gap-2 mt-2">
                        {rec.techniques.map((t: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}