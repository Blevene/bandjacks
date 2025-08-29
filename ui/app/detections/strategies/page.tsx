"use client";

import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Shield,
  Search,
  Filter,
  Loader2,
  ChevronRight,
  Target,
  Activity,
  AlertTriangle,
  CheckCircle
} from "lucide-react";
import Link from "next/link";

function DetectionStrategiesContent() {
  const searchParams = useSearchParams();
  const techniqueFilter = searchParams.get("technique");
  
  const [strategies, setStrategies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPlatform, setSelectedPlatform] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const { toast } = useToast();

  useEffect(() => {
    fetchStrategies();
  }, [techniqueFilter, selectedPlatform]);

  const fetchStrategies = async () => {
    setLoading(true);
    try {
      const result = await typedApi.detections.getStrategies({
        technique_id: techniqueFilter || undefined,
        platform: selectedPlatform || undefined,
        include_revoked: false,
        include_deprecated: false,
        limit: 100,
      });
      setStrategies(result || []);
    } catch (error: any) {
      toast({
        title: "Error loading strategies",
        description: error.response?.data?.detail || "Failed to load detection strategies",
        variant: "destructive",
      });
      setStrategies([]);
    } finally {
      setLoading(false);
    }
  };

  const filteredStrategies = strategies.filter(strategy => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      (strategy.name && strategy.name.toLowerCase().includes(query)) ||
      (strategy.description && strategy.description.toLowerCase().includes(query)) ||
      (strategy.analytic_id && strategy.analytic_id.toLowerCase().includes(query))
    );
  });

  const getConfidenceColor = (confidence: string) => {
    switch (confidence?.toLowerCase()) {
      case "high":
        return "bg-green-500/20 text-green-500";
      case "medium":
        return "bg-yellow-500/20 text-yellow-500";
      case "low":
        return "bg-red-500/20 text-red-500";
      default:
        return "bg-gray-500/20 text-gray-500";
    }
  };

  const platforms = ["Windows", "Linux", "macOS", "Cloud", "Network"];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Detection Strategies</h1>
        <p className="text-muted-foreground">
          Browse and manage detection analytics for ATT&CK techniques
        </p>
      </div>

      <Card>
        <CardContent className="p-6">
          <div className="space-y-4">
            <div className="flex gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search strategies by name or description..."
                  className="w-full pl-10 pr-4 py-2 border rounded-md bg-background"
                />
              </div>
              
              <select
                value={selectedPlatform}
                onChange={(e) => setSelectedPlatform(e.target.value)}
                className="px-4 py-2 border rounded-md bg-background"
              >
                <option value="">All Platforms</option>
                {platforms.map(platform => (
                  <option key={platform} value={platform}>{platform}</option>
                ))}
              </select>
            </div>

            {techniqueFilter && (
              <div className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 rounded-md">
                <Filter className="h-4 w-4 text-blue-500" />
                <span className="text-sm">
                  Filtering by technique: <strong>{techniqueFilter}</strong>
                </span>
                <button
                  onClick={() => window.location.href = "/detections/strategies"}
                  className="ml-auto text-xs text-blue-500 hover:underline"
                >
                  Clear filter
                </button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Strategies</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{filteredStrategies.length}</div>
            <p className="text-xs text-muted-foreground">
              Available detections
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Confidence</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filteredStrategies.filter(s => s.confidence === "high").length}
            </div>
            <p className="text-xs text-muted-foreground">
              Reliable detections
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coverage</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {new Set(filteredStrategies.map(s => s.technique_id)).size}
            </div>
            <p className="text-xs text-muted-foreground">
              Unique techniques
            </p>
          </CardContent>
        </Card>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : filteredStrategies.length > 0 ? (
        <div className="grid gap-4">
          {filteredStrategies.map((strategy, idx) => (
            <Link
              key={idx}
              href={`/detections/analytics/${strategy.analytic_id}`}
            >
              <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-blue-500" />
                        <h3 className="font-semibold">
                          {strategy.name || strategy.analytic_id}
                        </h3>
                        {strategy.confidence && (
                          <span className={`px-2 py-0.5 text-xs rounded ${getConfidenceColor(strategy.confidence)}`}>
                            {strategy.confidence}
                          </span>
                        )}
                      </div>
                      
                      {strategy.description && (
                        <p className="text-sm text-muted-foreground line-clamp-2">
                          {strategy.description}
                        </p>
                      )}
                      
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        {strategy.technique_id && (
                          <span className="flex items-center gap-1">
                            <Target className="h-3 w-3" />
                            {strategy.technique_id}
                          </span>
                        )}
                        {strategy.platform && (
                          <span className="flex items-center gap-1">
                            <Activity className="h-3 w-3" />
                            {strategy.platform}
                          </span>
                        )}
                        {strategy.data_sources && strategy.data_sources.length > 0 && (
                          <span>
                            {strategy.data_sources.length} data sources
                          </span>
                        )}
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="py-12 text-center">
            <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
            <p className="text-muted-foreground">
              {searchQuery || techniqueFilter || selectedPlatform
                ? "No strategies found matching your filters"
                : "No detection strategies available"}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function DetectionStrategiesPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    }>
      <DetectionStrategiesContent />
    </Suspense>
  );
}