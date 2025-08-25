"use client";

import { useState, useCallback } from "react";
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
  Panel,
} from "reactflow";
import "reactflow/dist/style.css";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Plus,
  Save,
  Play,
  Download,
  Trash2,
  GitBranch,
  Target,
  Shield,
  ChevronLeft,
  Settings,
  Activity
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

const initialNodes: Node[] = [
  {
    id: "1",
    type: "input",
    data: { label: "Initial Access" },
    position: { x: 250, y: 0 },
  },
];

const initialEdges: Edge[] = [];

export default function FlowBuilderPage() {
  const router = useRouter();
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [flowName, setFlowName] = useState("New Attack Flow");
  const [flowDescription, setFlowDescription] = useState("");
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [techniqueSearch, setTechniqueSearch] = useState("");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const { toast } = useToast();

  const onConnect = useCallback(
    (params: Connection) => {
      const edge = {
        ...params,
        type: "smoothstep",
        animated: true,
        markerEnd: {
          type: MarkerType.ArrowClosed,
        },
      };
      setEdges((eds) => addEdge(edge, eds));
    },
    [setEdges]
  );

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNode(node);
  }, []);

  const addTechniqueNode = (technique: any) => {
    const newNode: Node = {
      id: `node-${Date.now()}`,
      type: "default",
      data: {
        label: technique.name,
        technique_id: technique.external_id,
        stix_id: technique.stix_id,
      },
      position: {
        x: Math.random() * 500,
        y: Math.random() * 500,
      },
    };
    
    setNodes((nds) => nds.concat(newNode));
    setTechniqueSearch("");
    setSearchResults([]);
  };

  const searchTechniques = async () => {
    if (!techniqueSearch) return;
    
    try {
      const response = await fetch("http://localhost:8001/v1/search/ttx", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          text: techniqueSearch,
          top_k: 5,
        }),
      });
      
      if (response.ok) {
        const data = await response.json();
        setSearchResults(data.results || []);
      }
    } catch (error) {
      console.error("Error searching techniques:", error);
    }
  };

  const saveFlow = async () => {
    try {
      // Convert nodes and edges to attack flow format
      const flowData = {
        name: flowName,
        description: flowDescription,
        actions: nodes.map((node) => ({
          id: node.id,
          name: node.data.label,
          technique_id: node.data.technique_id,
          position: node.position,
        })),
        sequence: edges.map((edge) => ({
          from: edge.source,
          to: edge.target,
        })),
      };
      
      const response = await fetch("http://localhost:8001/v1/attackflow/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(flowData),
      });
      
      if (response.ok) {
        const result = await response.json();
        toast({
          title: "Flow saved",
          description: `Attack flow "${flowName}" has been saved successfully`,
        });
        
        // Navigate to the flow detail page
        if (result.flow_id) {
          router.push(`/flows/${result.flow_id}`);
        }
      } else {
        throw new Error("Failed to save flow");
      }
    } catch (error) {
      console.error("Error saving flow:", error);
      toast({
        title: "Error saving flow",
        description: "Failed to save the attack flow",
        variant: "destructive",
      });
    }
  };

  const deleteNode = () => {
    if (selectedNode) {
      setNodes((nds) => nds.filter((n) => n.id !== selectedNode.id));
      setEdges((eds) => eds.filter((e) => e.source !== selectedNode.id && e.target !== selectedNode.id));
      setSelectedNode(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/flows">
            <button className="p-2 hover:bg-muted rounded-md">
              <ChevronLeft className="h-5 w-5" />
            </button>
          </Link>
          <div>
            <input
              type="text"
              value={flowName}
              onChange={(e) => setFlowName(e.target.value)}
              className="text-2xl font-bold bg-transparent border-none outline-none"
              placeholder="Flow name"
            />
            <input
              type="text"
              value={flowDescription}
              onChange={(e) => setFlowDescription(e.target.value)}
              className="text-sm text-muted-foreground bg-transparent border-none outline-none w-full"
              placeholder="Flow description"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={saveFlow}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Save className="h-4 w-4" />
            Save Flow
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

      <div className="grid grid-cols-4 gap-4">
        <div className="col-span-1 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Add Technique</CardTitle>
              <CardDescription>Search and add techniques to the flow</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={techniqueSearch}
                    onChange={(e) => setTechniqueSearch(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && searchTechniques()}
                    placeholder="Search techniques..."
                    className="flex-1 px-3 py-2 border rounded-md"
                  />
                  <button
                    onClick={searchTechniques}
                    className="px-3 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                  >
                    Search
                  </button>
                </div>
                
                {searchResults.length > 0 && (
                  <div className="space-y-2">
                    {searchResults.map((result) => (
                      <div
                        key={result.stix_id}
                        onClick={() => addTechniqueNode(result)}
                        className="p-2 border rounded-md hover:bg-muted cursor-pointer"
                      >
                        <div className="flex items-center gap-2">
                          <Target className="h-4 w-4 text-red-500" />
                          <div className="flex-1">
                            <p className="text-sm font-medium">{result.name}</p>
                            {result.external_id && (
                              <p className="text-xs text-muted-foreground">{result.external_id}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Node Properties</CardTitle>
              <CardDescription>
                {selectedNode ? `Editing: ${selectedNode.data.label}` : "Select a node to edit"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {selectedNode ? (
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium">Label</label>
                    <input
                      type="text"
                      value={selectedNode.data.label}
                      onChange={(e) => {
                        const newNodes = nodes.map((node) => {
                          if (node.id === selectedNode.id) {
                            node.data = {
                              ...node.data,
                              label: e.target.value,
                            };
                          }
                          return node;
                        });
                        setNodes(newNodes);
                      }}
                      className="w-full px-3 py-2 border rounded-md mt-1"
                    />
                  </div>
                  
                  {selectedNode.data.technique_id && (
                    <div>
                      <label className="text-sm font-medium">Technique ID</label>
                      <p className="text-sm text-muted-foreground mt-1">
                        {selectedNode.data.technique_id}
                      </p>
                    </div>
                  )}
                  
                  <button
                    onClick={deleteNode}
                    className="flex items-center gap-2 px-3 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 w-full"
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete Node
                  </button>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No node selected
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Flow Stats</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Nodes:</span>
                  <span className="font-medium">{nodes.length}</span>
                </div>
                <div className="flex justify-between">
                  <span>Edges:</span>
                  <span className="font-medium">{edges.length}</span>
                </div>
                <div className="flex justify-between">
                  <span>Complexity:</span>
                  <span className="font-medium">
                    {nodes.length <= 3 ? "Low" : nodes.length <= 7 ? "Medium" : "High"}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="col-span-3">
          <Card className="h-[700px]">
            <CardContent className="p-0 h-full">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={onNodeClick}
                fitView
              >
                <Panel position="top-left">
                  <div className="bg-background/80 backdrop-blur p-2 rounded-md">
                    <p className="text-xs text-muted-foreground">
                      Click and drag to pan • Scroll to zoom • Click nodes to select • Drag from handles to connect
                    </p>
                  </div>
                </Panel>
                <Background gap={12} size={1} />
                <Controls />
                <MiniMap />
              </ReactFlow>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}