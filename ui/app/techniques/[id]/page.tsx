"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Tag,
  FileText,
  GitBranch,
  Users,
  Target,
  Activity,
  ExternalLink,
  ChevronRight,
  Layers,
  Database,
  Package
} from "lucide-react";
import Link from "next/link";

export default function TechniquePage() {
  const params = useParams();
  const techniqueId = params.id as string;
  const [technique, setTechnique] = useState<any>(null);
  const [strategies, setStrategies] = useState<any[]>([]);
  const [usageData, setUsageData] = useState<{ 
    groups: any[], 
    software: any[], 
    campaigns?: any[],
    mitigations?: any[],
    detectionStrategies?: any[],
    analytics?: any[],
    defensiveTechniques?: any[],
    reports?: any[],
    sightings?: any[],
    edges?: any
  }>({ groups: [], software: [], campaigns: [] });
  const [loading, setLoading] = useState(true);
  const [loadingStrategies, setLoadingStrategies] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (techniqueId) {
      fetchTechniqueDetails();
    }
  }, [techniqueId]);
  
  useEffect(() => {
    if (technique) {
      fetchDetectionStrategies();
    }
  }, [technique]);

  const fetchTechniqueDetails = async () => {
    try {
      let stixId = techniqueId;
      let techniqueData = null;
      let externalId = null;
      
      // Check if it's a STIX ID or external ID
      if (techniqueId.startsWith('attack-pattern--')) {
        // It's a STIX ID, get the node data via subgraph
        const subgraphResponse = await fetch(
          `http://localhost:8001/v1/graph/subgraph?expand_depth=0`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify([techniqueId])
          }
        );
        
        if (subgraphResponse.ok) {
          const graphData = await subgraphResponse.json();
          // Find our technique node in the nodes array
          const node = graphData.nodes?.find((n: any) => n.stix_id === techniqueId);
          if (node) {
            techniqueData = node;
            stixId = techniqueId;
            
            // Try to extract external_id from properties if it exists
            if (node.properties?.external_id) {
              externalId = node.properties.external_id;
            } else if (node.external_id) {
              externalId = node.external_id;
            }
          }
        }
        
        // If we have the name, try to search for more details including external_id
        if (techniqueData?.name) {
          try {
            const searchResult = await typedApi.search.ttx({
              text: techniqueData.name,
              top_k: 5,
            });
            
            // Find matching technique by name or STIX ID
            const match = searchResult.results?.find((r: any) => 
              r.stix_id === techniqueId || r.name === techniqueData.name
            );
            
            if (match) {
              externalId = match.external_id;
              // Merge the search result data
              techniqueData = { ...techniqueData, ...match };
            }
          } catch (e) {
            console.error('Search failed:', e);
          }
        }
        
        // Get coverage if we have external_id
        if (externalId) {
          try {
            const coverage = await typedApi.coverage.getTechnique(externalId);
            techniqueData = { ...techniqueData, ...coverage, external_id: externalId };
          } catch (e) {
            console.error('Coverage fetch failed:', e);
          }
        }
      } else {
        // It's likely an external ID (like T1124), search for it
        const searchResult = await typedApi.search.ttx({
          text: techniqueId,
          top_k: 1,
        });
        
        if (searchResult.results && searchResult.results.length > 0) {
          const result = searchResult.results[0];
          techniqueData = result;
          stixId = result.stix_id;
          externalId = result.external_id || techniqueId;
          
          // Get coverage details
          if (externalId) {
            try {
              const coverage = await typedApi.coverage.getTechnique(externalId);
              techniqueData = { ...techniqueData, ...coverage };
            } catch (e) {
              console.error('Coverage fetch failed:', e);
            }
          }
        }
      }
      
      if (techniqueData) {
        setTechnique(techniqueData);
        // Fetch usage data if we have a STIX ID
        if (stixId) {
          fetchUsageData(stixId);
        }
      } else {
        // Technique not found
        setTechnique(null);
      }
    } catch (error: any) {
      console.error('Error in fetchTechniqueDetails:', error);
      toast({
        title: "Error loading technique",
        description: error.response?.data?.detail || "Failed to load technique details",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchUsageData = async (stixId: string) => {
    try {
      // We need to make multiple specific queries for different relationship types
      // because the subgraph endpoint has limitations
      
      // 1. Get entities that USE this technique (incoming USES)
      const usersResponse = await fetch(
        `http://localhost:8001/v1/graph/neighbors/${encodeURIComponent(stixId)}?edge_types=USES&direction=in`
      );
      
      // 2. Get mitigations (incoming MITIGATES)
      const mitigationsResponse = await fetch(
        `http://localhost:8001/v1/graph/neighbors/${encodeURIComponent(stixId)}?edge_types=MITIGATES&direction=in`
      );
      
      // 3. Get detection strategies (incoming DETECTS)
      const detectionsResponse = await fetch(
        `http://localhost:8001/v1/graph/neighbors/${encodeURIComponent(stixId)}?edge_types=DETECTS&direction=in`
      );
      
      // 4. Get D3FEND countermeasures (incoming COUNTERS)
      const countersResponse = await fetch(
        `http://localhost:8001/v1/graph/neighbors/${encodeURIComponent(stixId)}?edge_types=COUNTERS&direction=in`
      );
      
      // 5. Get general subgraph for additional context
      const subgraphResponse = await fetch(
        `http://localhost:8001/v1/graph/subgraph?expand_depth=2`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify([stixId])
        }
      );
      
      // Process all responses
      const [users, mitigations, detections, counters, subgraph] = await Promise.all([
        usersResponse.ok ? usersResponse.json() : { neighbors: [] },
        mitigationsResponse.ok ? mitigationsResponse.json() : { neighbors: [] },
        detectionsResponse.ok ? detectionsResponse.json() : { neighbors: [] },
        countersResponse.ok ? countersResponse.json() : { neighbors: [] },
        subgraphResponse.ok ? subgraphResponse.json() : { nodes: [], edges: [] }
      ]);
      
      // Combine all nodes, deduplicating by stix_id
      const allNodes = new Map();
      
      // Add nodes from each response
      [...(users.neighbors || []), 
       ...(mitigations.neighbors || []),
       ...(detections.neighbors || []),
       ...(counters.neighbors || []),
       ...(subgraph.nodes || [])].forEach(node => {
        if (node.stix_id) {
          allNodes.set(node.stix_id, node);
        }
      });
      
      const nodes = Array.from(allNodes.values());
      
      // Categorize nodes by type
      const software = nodes.filter((n: any) => 
        n.type === 'malware' || n.type === 'tool' || n.type === 'software'
      );
      
      const groups = nodes.filter((n: any) => n.type === 'intrusion-set');
      const campaigns = nodes.filter((n: any) => n.type === 'campaign');
      const mitigationNodes = nodes.filter((n: any) => 
        n.type === 'mitigation' || n.type === 'course-of-action'
      );
      const detectionStrategies = nodes.filter((n: any) => 
        n.type === 'x-mitre-detection-strategy' || n.type === 'detection-strategy'
      );
      const analytics = nodes.filter((n: any) => n.type === 'x-mitre-analytic');
      const defensiveTechniques = nodes.filter((n: any) => 
        n.label === 'DefensiveTechnique' || n.type === 'd3fend-technique' || n.type === 'defensive-technique'
      );
      const reports = nodes.filter((n: any) => n.type === 'report');
      const sightings = nodes.filter((n: any) => n.type === 'sighting');
      
      // Log what we found for debugging
      console.log('Relationship data fetched:', {
        users: users.neighbors?.length || 0,
        mitigations: mitigations.neighbors?.length || 0,
        detections: detections.neighbors?.length || 0,
        counters: counters.neighbors?.length || 0,
        totalNodes: nodes.length
      });
      
      setUsageData({ 
        groups: groups,
        software: software,
        campaigns: campaigns,
        mitigations: mitigationNodes,
        detectionStrategies: detectionStrategies,
        analytics: analytics,
        defensiveTechniques: defensiveTechniques,
        reports: reports,
        sightings: sightings,
        edges: {
          uses: users.relationships || [],
          mitigates: mitigations.relationships || [],
          detects: detections.relationships || [],
          counters: counters.relationships || []
        }
      });
    } catch (error) {
      console.error('Failed to fetch usage data:', error);
    }
  };

  const fetchDetectionStrategies = async () => {
    setLoadingStrategies(true);
    try {
      // Try with the current techniqueId first (might be external ID or STIX ID)
      let searchId = techniqueId;
      
      // If it's a STIX ID, we might need to get the external ID
      if (techniqueId.startsWith('attack-pattern--') && technique?.external_id) {
        searchId = technique.external_id;
      }
      
      const result = await typedApi.detections.getStrategies({
        technique_id: searchId,
        limit: 20,
      });
      setStrategies(result.strategies || []);
    } catch (error: any) {
      // Strategies might not exist, which is okay
      setStrategies([]);
    } finally {
      setLoadingStrategies(false);
    }
  };

  const getCoverageColor = (score: number) => {
    if (score >= 0.8) return "text-green-500";
    if (score >= 0.5) return "text-yellow-500";
    return "text-red-500";
  };

  const getCoverageLabel = (score: number) => {
    if (score >= 0.8) return "High Coverage";
    if (score >= 0.5) return "Moderate Coverage";
    return "Low Coverage";
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!technique) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <p className="text-lg font-medium">Technique not found</p>
          <p className="text-sm text-muted-foreground mt-2">
            The technique "{techniqueId}" could not be found.
          </p>
          <Link href="/search">
            <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
              Back to Search
            </button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-2">
          <h1 className="text-3xl font-bold tracking-tight">{technique.name}</h1>
          {technique.external_id && (
            <span className="px-3 py-1 text-sm bg-blue-500/20 text-blue-500 rounded-md font-medium">
              {technique.external_id}
            </span>
          )}
        </div>
        <p className="text-muted-foreground">
          {technique.description || "No description available"}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coverage Score</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getCoverageColor(technique.coverage_score || 0)}`}>
              {((technique.coverage_score || 0) * 100).toFixed(0)}%
            </div>
            <p className="text-xs text-muted-foreground">
              {getCoverageLabel(technique.coverage_score || 0)}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Detection Strategies</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{strategies.length}</div>
            <p className="text-xs text-muted-foreground">
              Available strategies
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Sub-techniques</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {technique.subtechnique_count || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Related sub-techniques
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Version</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {technique.attack_version || "17.1"}
            </div>
            <p className="text-xs text-muted-foreground">
              ATT&CK version
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Technique Details</CardTitle>
            <CardDescription>Metadata and classification</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {technique.tactics && technique.tactics.length > 0 && (
              <div className="flex items-start gap-2">
                <Tag className="h-4 w-4 text-blue-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Tactics</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {technique.tactics.map((tactic: string, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-secondary rounded">
                        {tactic}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {technique.platforms && technique.platforms.length > 0 && (
              <div className="flex items-start gap-2">
                <FileText className="h-4 w-4 text-green-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Platforms</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {technique.platforms.map((platform: string, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-secondary rounded">
                        {platform}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {technique.data_sources && technique.data_sources.length > 0 && (
              <div className="flex items-start gap-2">
                <Activity className="h-4 w-4 text-purple-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Data Sources</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {technique.data_sources.slice(0, 5).map((source: string, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-secondary rounded">
                        {source}
                      </span>
                    ))}
                    {technique.data_sources.length > 5 && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{technique.data_sources.length - 5} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {technique.mitigation_count !== undefined && (
              <div className="flex items-start gap-2">
                <Shield className="h-4 w-4 text-orange-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Mitigations</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {technique.mitigation_count} available mitigations
                  </p>
                </div>
              </div>
            )}

            {(usageData.groups.length > 0 || technique.groups?.length > 0) && (
              <div className="flex items-start gap-2">
                <Users className="h-4 w-4 text-red-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Known Groups ({usageData.groups.length || technique.groups?.length || 0})</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {(usageData.groups.length > 0 ? usageData.groups : technique.groups || [])
                      .slice(0, 3)
                      .map((group: any, idx: number) => (
                        <span key={idx} className="px-2 py-0.5 text-xs bg-red-500/20 text-red-500 rounded">
                          {group.name || group}
                        </span>
                      ))}
                    {((usageData.groups.length || technique.groups?.length || 0) > 3) && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{(usageData.groups.length || technique.groups?.length || 0) - 3} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {usageData.software.length > 0 && (
              <div className="flex items-start gap-2">
                <Package className="h-4 w-4 text-blue-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Used by Software ({usageData.software.length})</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {usageData.software.slice(0, 3).map((sw: any, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-500 rounded">
                        {sw.name || sw.stix_id}
                      </span>
                    ))}
                    {usageData.software.length > 3 && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{usageData.software.length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {usageData.campaigns && usageData.campaigns.length > 0 && (
              <div className="flex items-start gap-2">
                <GitBranch className="h-4 w-4 text-purple-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Associated Campaigns ({usageData.campaigns.length})</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {usageData.campaigns.slice(0, 3).map((campaign: any, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-500 rounded">
                        {campaign.name || campaign.stix_id}
                      </span>
                    ))}
                    {usageData.campaigns.length > 3 && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{usageData.campaigns.length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
            
            {usageData.mitigations && usageData.mitigations.length > 0 && (
              <div className="flex items-start gap-2">
                <Shield className="h-4 w-4 text-green-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Mitigations ({usageData.mitigations.length})</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {usageData.mitigations.slice(0, 3).map((mitigation: any, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-green-500/20 text-green-500 rounded">
                        {mitigation.name || mitigation.stix_id}
                      </span>
                    ))}
                    {usageData.mitigations.length > 3 && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{usageData.mitigations.length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
            
            {usageData.defensiveTechniques && usageData.defensiveTechniques.length > 0 && (
              <div className="flex items-start gap-2">
                <Shield className="h-4 w-4 text-cyan-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">D3FEND Countermeasures ({usageData.defensiveTechniques.length})</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {usageData.defensiveTechniques.slice(0, 3).map((defense: any, idx: number) => (
                      <span key={idx} className="px-2 py-0.5 text-xs bg-cyan-500/20 text-cyan-500 rounded">
                        {defense.name || defense.id}
                      </span>
                    ))}
                    {usageData.defensiveTechniques.length > 3 && (
                      <span className="px-2 py-0.5 text-xs text-muted-foreground">
                        +{usageData.defensiveTechniques.length - 3} more
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}
            
            {usageData.sightings && usageData.sightings.length > 0 && (
              <div className="flex items-start gap-2">
                <Activity className="h-4 w-4 text-amber-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium">Sightings ({usageData.sightings.length})</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Observed in {usageData.sightings.length} real-world incidents
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Detection Strategies</CardTitle>
            <CardDescription>
              {loadingStrategies ? "Loading..." : `${strategies.length} strategies available`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loadingStrategies ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : strategies.length > 0 ? (
              <div className="space-y-3">
                {strategies.slice(0, 5).map((strategy, idx) => (
                  <Link
                    key={idx}
                    href={`/detections/analytics/${strategy.analytic_id}`}
                  >
                    <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors cursor-pointer">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {strategy.name || strategy.analytic_id}
                          </p>
                          {strategy.description && (
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                              {strategy.description}
                            </p>
                          )}
                          <div className="flex items-center gap-2 mt-2">
                            {strategy.confidence && (
                              <span className={`text-xs px-2 py-0.5 rounded ${
                                strategy.confidence === "high" 
                                  ? "bg-green-500/20 text-green-500"
                                  : strategy.confidence === "medium"
                                  ? "bg-yellow-500/20 text-yellow-500"
                                  : "bg-red-500/20 text-red-500"
                              }`}>
                                {strategy.confidence}
                              </span>
                            )}
                            {strategy.platform && (
                              <span className="text-xs text-muted-foreground">
                                {strategy.platform}
                              </span>
                            )}
                          </div>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </div>
                  </Link>
                ))}
                {strategies.length > 5 && (
                  <Link href={`/detections/strategies?technique=${techniqueId}`}>
                    <p className="text-sm text-primary hover:underline cursor-pointer text-center">
                      View all {strategies.length} strategies →
                    </p>
                  </Link>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <AlertTriangle className="h-8 w-8 text-yellow-500 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  No detection strategies available for this technique
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {technique.references && technique.references.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>References</CardTitle>
            <CardDescription>External documentation and resources</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {technique.references.slice(0, 5).map((ref: any, idx: number) => (
                <a
                  key={idx}
                  href={ref.url || ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm text-primary hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  {ref.source || ref.url || ref}
                </a>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}