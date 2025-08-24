"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { 
  Shield,
  Target,
  Loader2,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Activity,
  Layers,
  BarChart,
  Server,
  Hash
} from "lucide-react";
import Link from "next/link";

// Simplified component without usage data fetching for performance
function TechniqueCard({ technique }: { technique: any }) {
  // The coverage API returns 'id' which is the STIX ID
  const techniqueId = technique.id || technique.stix_id;
  
  // Only render if we have a valid ID
  if (!techniqueId) {
    return null;
  }
  
  return (
    <Link href={`/techniques/${encodeURIComponent(techniqueId)}`}>
      <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors cursor-pointer">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-red-500" />
              <span className="text-sm font-medium">
                {technique.name || "Unknown Technique"}
              </span>
              {technique.external_id && (
                <span className="text-xs text-muted-foreground">
                  ({technique.external_id})
                </span>
              )}
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        </div>
      </div>
    </Link>
  );
}

const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development", 
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact"
];

const TACTIC_COLORS: Record<string, string> = {
  "Reconnaissance": "bg-gray-500",
  "Resource Development": "bg-slate-500",
  "Initial Access": "bg-red-500",
  "Execution": "bg-orange-500",
  "Persistence": "bg-amber-500",
  "Privilege Escalation": "bg-yellow-500",
  "Defense Evasion": "bg-lime-500",
  "Credential Access": "bg-green-500",
  "Discovery": "bg-emerald-500",
  "Lateral Movement": "bg-teal-500",
  "Collection": "bg-cyan-500",
  "Command and Control": "bg-sky-500",
  "Exfiltration": "bg-blue-500",
  "Impact": "bg-purple-500"
};

export default function TechniquesPage() {
  const [coverage, setCoverage] = useState<any>(null);
  const [techniques, setTechniques] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  useEffect(() => {
    fetchData();
  }, []);
  
  const fetchData = async () => {
    try {
      // Fetch both coverage and all techniques in parallel
      const [coverageResult, techniquesResult] = await Promise.all([
        typedApi.coverage.getAggregated(),
        fetch('http://localhost:8001/v1/catalog/techniques').then(r => r.json())
      ]);
      
      console.log('Coverage data received:', coverageResult);
      console.log('Techniques data received:', techniquesResult);
      
      setCoverage(coverageResult);
      setTechniques(techniquesResult);
    } catch (error: any) {
      console.error('Error fetching data:', error);
      toast({
        title: "Error loading techniques",
        description: error.response?.data?.detail || "Failed to load techniques data",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };


  const toggleTactic = (tactic: string) => {
    const newExpanded = new Set(expandedTactics);
    if (newExpanded.has(tactic)) {
      newExpanded.delete(tactic);
    } else {
      newExpanded.add(tactic);
    }
    setExpandedTactics(newExpanded);
  };

  const getCoverageColor = (percentage: number) => {
    if (percentage >= 75) return "text-green-500";
    if (percentage >= 50) return "text-yellow-500";
    if (percentage >= 25) return "text-orange-500";
    return "text-red-500";
  };

  const getCoverageIcon = (percentage: number) => {
    if (percentage >= 75) return <CheckCircle className="h-5 w-5 text-green-500" />;
    if (percentage >= 50) return <Activity className="h-5 w-5 text-yellow-500" />;
    return <AlertTriangle className="h-5 w-5 text-red-500" />;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const sortedTactics = coverage?.tactics?.sort((a: any, b: any) => {
    const aIndex = TACTIC_ORDER.indexOf(a.tactic);
    const bIndex = TACTIC_ORDER.indexOf(b.tactic);
    return (aIndex === -1 ? 999 : aIndex) - (bIndex === -1 ? 999 : bIndex);
  }) || [];

  const totalTechniques = sortedTactics.reduce((sum: number, t: any) => sum + (t.technique_count || 0), 0);
  const totalCovered = sortedTactics.reduce((sum: number, t: any) => sum + (t.covered_count || 0), 0);
  const overallCoverage = totalTechniques > 0 ? (totalCovered / totalTechniques) * 100 : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">ATT&CK Techniques</h1>
        <p className="text-muted-foreground">
          Browse techniques organized by tactic with coverage analytics
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Techniques</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalTechniques}</div>
            <p className="text-xs text-muted-foreground">
              Across {sortedTactics.length} tactics
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coverage</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${getCoverageColor(overallCoverage)}`}>
              {overallCoverage.toFixed(1)}%
            </div>
            <p className="text-xs text-muted-foreground">
              {totalCovered} techniques covered
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Best Coverage</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sortedTactics[0]?.tactic || "N/A"}
            </div>
            <p className="text-xs text-muted-foreground">
              {sortedTactics[0]?.coverage_percentage?.toFixed(0)}% covered
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Needs Attention</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sortedTactics.filter((t: any) => t.coverage_percentage < 50).length}
            </div>
            <p className="text-xs text-muted-foreground">
              Tactics below 50% coverage
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <h2 className="text-xl font-semibold">Techniques by Tactic</h2>
        
        {sortedTactics.map((tacticData: any) => {
          const isExpanded = expandedTactics.has(tacticData.tactic);
          const color = TACTIC_COLORS[tacticData.tactic] || "bg-gray-500";
          
          // Find corresponding techniques data from the techniques API
          const tacticTechniques = techniques?.tactics?.find(
            (t: any) => t.tactic_name === tacticData.tactic
          );
          
          return (
            <Card key={tacticData.tactic} className="overflow-hidden">
              <CardHeader 
                className="cursor-pointer hover:bg-muted/50 transition-colors"
                onClick={() => toggleTactic(tacticData.tactic)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-1 h-12 ${color} rounded`} />
                    <div>
                      <CardTitle className="text-lg flex items-center gap-2">
                        {tacticData.tactic}
                        <span className="text-sm font-normal text-muted-foreground">
                          ({tacticTechniques?.technique_count || tacticData.technique_count} techniques)
                        </span>
                      </CardTitle>
                      <CardDescription className="mt-1">
                        <div className="flex items-center gap-4">
                          <span className="flex items-center gap-1">
                            {getCoverageIcon(tacticData.coverage_percentage)}
                            <span className={getCoverageColor(tacticData.coverage_percentage)}>
                              {tacticData.coverage_percentage.toFixed(1)}% covered
                            </span>
                          </span>
                          <span className="text-xs">
                            {tacticData.covered_count} of {tacticTechniques?.technique_count || tacticData.technique_count} techniques
                          </span>
                        </div>
                      </CardDescription>
                    </div>
                  </div>
                  {isExpanded ? (
                    <ChevronDown className="h-5 w-5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  )}
                </div>
              </CardHeader>
              
              {isExpanded && tacticTechniques && (
                <CardContent className="pt-0">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-sm text-muted-foreground mb-2">
                      <span>All Techniques in {tacticData.tactic}:</span>
                      <span className="text-xs">
                        {tacticTechniques.technique_count} total
                      </span>
                    </div>
                    
                    {/* Grid view of all techniques */}
                    <div className="grid gap-2 max-h-96 overflow-y-auto">
                      {tacticTechniques.techniques?.map((technique: any) => (
                        <Link 
                          key={technique.stix_id} 
                          href={`/techniques/${encodeURIComponent(technique.stix_id)}`}
                        >
                          <div className="p-3 border rounded-md hover:bg-muted/50 transition-colors cursor-pointer">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2">
                                  <Target className="h-4 w-4 text-red-500 flex-shrink-0" />
                                  <div className="flex-1">
                                    <span className="text-sm font-medium">
                                      {technique.name}
                                    </span>
                                    {technique.external_id && (
                                      <Badge variant="outline" className="ml-2 text-xs">
                                        {technique.external_id}
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                                {technique.description && (
                                  <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                    {technique.description}
                                  </p>
                                )}
                                {technique.platforms && technique.platforms.length > 0 && (
                                  <div className="flex gap-1 mt-2">
                                    {technique.platforms.slice(0, 3).map((platform: string) => (
                                      <Badge key={platform} variant="secondary" className="text-xs">
                                        {platform}
                                      </Badge>
                                    ))}
                                    {technique.platforms.length > 3 && (
                                      <span className="text-xs text-muted-foreground">
                                        +{technique.platforms.length - 3}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                              <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            </div>
                          </div>
                        </Link>
                      ))}
                    </div>

                    {/* Coverage summary at bottom */}
                    <div className="pt-3 border-t">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Coverage Distribution:</span>
                      </div>
                      <div className="mt-2 h-2 bg-secondary rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-green-500 transition-all"
                          style={{ width: `${tacticData.coverage_percentage}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-xs text-muted-foreground mt-1">
                        <span>{tacticData.covered_count} covered</span>
                        <span>{(tacticTechniques?.technique_count || tacticData.technique_count) - tacticData.covered_count} gaps</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Coverage Summary</CardTitle>
          <CardDescription>
            Overall detection coverage across the ATT&CK framework
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {sortedTactics.map((tacticData: any) => {
              const color = TACTIC_COLORS[tacticData.tactic] || "bg-gray-500";
              return (
                <div key={tacticData.tactic} className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium">{tacticData.tactic}</span>
                    <span className={getCoverageColor(tacticData.coverage_percentage)}>
                      {tacticData.coverage_percentage.toFixed(1)}%
                    </span>
                  </div>
                  <div className="h-2 bg-secondary rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${color} opacity-70 transition-all`}
                      style={{ width: `${tacticData.coverage_percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}