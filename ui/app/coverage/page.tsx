"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  Layers,
  Monitor,
  Cloud,
  Server,
  Smartphone,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Download,
  Filter,
  Loader2,
  ChevronRight
} from "lucide-react";
import Link from "next/link";

interface HeatmapCell {
  tactic: string;
  platform: string;
  technique_count: number;
  covered_count: number;
  coverage_percentage: number;
  techniques: Array<{
    id: string;
    name: string;
    covered: boolean;
  }>;
}

interface CoverageData {
  heatmap: HeatmapCell[];
  tactics: string[];
  platforms: string[];
  summary: {
    total_cells: number;
    fully_covered: number;
    partially_covered: number;
    no_coverage: number;
  };
}

const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact"
];

const PLATFORM_ICONS: Record<string, any> = {
  "Windows": Monitor,
  "Linux": Server,
  "macOS": Monitor,
  "Cloud": Cloud,
  "Mobile": Smartphone,
  "Network": Server,
  "Container": Server,
};

export default function CoveragePage() {
  const [coverageData, setCoverageData] = useState<CoverageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCell, setSelectedCell] = useState<HeatmapCell | null>(null);
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>([]);
  const [selectedTactics, setSelectedTactics] = useState<string[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    fetchCoverageData();
  }, []);

  const fetchCoverageData = async () => {
    try {
      const response = await fetch("http://localhost:8001/v1/analytics/coverage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          tactics: selectedTactics.length > 0 ? selectedTactics : undefined,
          platforms: selectedPlatforms.length > 0 ? selectedPlatforms : undefined,
          include_sub_techniques: true,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        
        // Transform the data into heatmap format
        const heatmap: HeatmapCell[] = [];
        const tactics = new Set<string>();
        const platforms = new Set<string>();
        
        // Create heatmap cells from the response
        data.tactics?.forEach((tacticData: any) => {
          tactics.add(tacticData.tactic);
          
          // For each platform, create a cell
          data.platforms?.forEach((platformData: any) => {
            platforms.add(platformData.platform);
            
            // Calculate intersection coverage
            const cell: HeatmapCell = {
              tactic: tacticData.tactic,
              platform: platformData.platform,
              technique_count: 0,
              covered_count: 0,
              coverage_percentage: 0,
              techniques: []
            };
            
            // This is simplified - in production you'd calculate actual intersection
            if (platformData.tactics_breakdown && platformData.tactics_breakdown[tacticData.tactic]) {
              cell.coverage_percentage = platformData.tactics_breakdown[tacticData.tactic];
              cell.technique_count = tacticData.technique_count;
              cell.covered_count = Math.round(tacticData.technique_count * cell.coverage_percentage / 100);
            }
            
            heatmap.push(cell);
          });
        });
        
        const transformedData: CoverageData = {
          heatmap,
          tactics: Array.from(tactics).sort((a, b) => {
            const aIndex = TACTIC_ORDER.indexOf(a.toLowerCase());
            const bIndex = TACTIC_ORDER.indexOf(b.toLowerCase());
            if (aIndex === -1 && bIndex === -1) return a.localeCompare(b);
            if (aIndex === -1) return 1;
            if (bIndex === -1) return -1;
            return aIndex - bIndex;
          }),
          platforms: Array.from(platforms).sort(),
          summary: {
            total_cells: heatmap.length,
            fully_covered: heatmap.filter(c => c.coverage_percentage === 100).length,
            partially_covered: heatmap.filter(c => c.coverage_percentage > 0 && c.coverage_percentage < 100).length,
            no_coverage: heatmap.filter(c => c.coverage_percentage === 0).length,
          }
        };
        
        setCoverageData(transformedData);
      }
    } catch (error) {
      console.error("Error fetching coverage data:", error);
      toast({
        title: "Error",
        description: "Failed to load coverage data",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const getCellColor = (percentage: number) => {
    if (percentage === 0) return "bg-red-500/20 hover:bg-red-500/30";
    if (percentage < 25) return "bg-red-400/20 hover:bg-red-400/30";
    if (percentage < 50) return "bg-orange-400/20 hover:bg-orange-400/30";
    if (percentage < 75) return "bg-yellow-400/20 hover:bg-yellow-400/30";
    if (percentage < 100) return "bg-green-400/20 hover:bg-green-400/30";
    return "bg-green-500/20 hover:bg-green-500/30";
  };

  const getCellTextColor = (percentage: number) => {
    if (percentage === 0) return "text-red-600";
    if (percentage < 50) return "text-orange-600";
    if (percentage < 100) return "text-yellow-600";
    return "text-green-600";
  };

  const handleCellClick = (cell: HeatmapCell) => {
    setSelectedCell(cell);
  };

  const exportHeatmap = () => {
    if (!coverageData) return;
    
    const csv = [
      ["Tactic", "Platform", "Coverage %", "Techniques Covered", "Total Techniques"],
      ...coverageData.heatmap.map(cell => [
        cell.tactic,
        cell.platform,
        cell.coverage_percentage.toFixed(1),
        cell.covered_count.toString(),
        cell.technique_count.toString()
      ])
    ].map(row => row.join(",")).join("\n");
    
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "coverage_heatmap.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!coverageData) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <p className="text-lg font-medium">No coverage data available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Coverage Heatmap</h1>
          <p className="text-muted-foreground">
            Detection coverage across tactics and platforms
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/analytics">
            <button className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted">
              <Layers className="h-4 w-4" />
              Analytics
            </button>
          </Link>
          <button
            onClick={exportHeatmap}
            className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Coverage</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {coverageData.summary.total_cells > 0
                ? `${((coverageData.summary.fully_covered / coverageData.summary.total_cells) * 100).toFixed(0)}%`
                : "0%"}
            </div>
            <p className="text-xs text-muted-foreground">
              Fully covered cells
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Full Coverage</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">
              {coverageData.summary.fully_covered}
            </div>
            <p className="text-xs text-muted-foreground">
              100% covered cells
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Partial Coverage</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-500">
              {coverageData.summary.partially_covered}
            </div>
            <p className="text-xs text-muted-foreground">
              1-99% covered cells
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">No Coverage</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">
              {coverageData.summary.no_coverage}
            </div>
            <p className="text-xs text-muted-foreground">
              0% covered cells
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Tactic × Platform Coverage Matrix</CardTitle>
              <CardDescription>
                Click on any cell to view technique-level details
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                <div className="w-4 h-4 bg-green-500/20 rounded" />
                <span>High (75-100%)</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-4 h-4 bg-yellow-400/20 rounded" />
                <span>Medium (25-75%)</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-4 h-4 bg-red-500/20 rounded" />
                <span>Low (0-25%)</span>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="text-left p-2 font-medium">Tactic / Platform</th>
                  {coverageData.platforms.map(platform => {
                    const Icon = PLATFORM_ICONS[platform] || Server;
                    return (
                      <th key={platform} className="text-center p-2 min-w-[100px]">
                        <div className="flex flex-col items-center gap-1">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                          <span className="text-xs font-medium">{platform}</span>
                        </div>
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {coverageData.tactics.map(tactic => (
                  <tr key={tactic}>
                    <td className="p-2 font-medium text-sm capitalize">
                      {tactic.replace("-", " ")}
                    </td>
                    {coverageData.platforms.map(platform => {
                      const cell = coverageData.heatmap.find(
                        c => c.tactic === tactic && c.platform === platform
                      );
                      if (!cell) return <td key={platform} className="p-2" />;
                      
                      return (
                        <td key={platform} className="p-2">
                          <button
                            onClick={() => handleCellClick(cell)}
                            className={`w-full p-3 rounded-md transition-colors ${getCellColor(cell.coverage_percentage)}`}
                          >
                            <div className="text-center">
                              <div className={`text-lg font-bold ${getCellTextColor(cell.coverage_percentage)}`}>
                                {cell.coverage_percentage.toFixed(0)}%
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {cell.covered_count}/{cell.technique_count}
                              </div>
                            </div>
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {selectedCell && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="capitalize">
                  {selectedCell.tactic.replace("-", " ")} on {selectedCell.platform}
                </CardTitle>
                <CardDescription>
                  {selectedCell.covered_count} of {selectedCell.technique_count} techniques covered
                </CardDescription>
              </div>
              <button
                onClick={() => setSelectedCell(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex items-center gap-2 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-md">
                <Info className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                <p className="text-sm">
                  Click below to drill down to specific technique coverage details
                </p>
              </div>
              <Link
                href={`/coverage/techniques?tactic=${selectedCell.tactic}&platform=${selectedCell.platform}`}
              >
                <button className="w-full flex items-center justify-between p-3 border rounded-md hover:bg-muted">
                  <span className="font-medium">View Technique Details</span>
                  <ChevronRight className="h-4 w-4" />
                </button>
              </Link>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}