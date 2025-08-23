"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Search as SearchIcon,
  GitBranch,
  Shield,
  ExternalLink,
  Loader2,
  FileText,
  Target,
  Users,
  Tag,
  ChevronRight
} from "lucide-react";
import Link from "next/link";

type SearchTab = "ttx" | "flows";

export default function SearchPage() {
  const [activeTab, setActiveTab] = useState<SearchTab>("ttx");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [ttxResults, setTtxResults] = useState<any[]>([]);
  const [flowResults, setFlowResults] = useState<any[]>([]);
  const { toast } = useToast();

  const handleTtxSearch = async () => {
    if (!query.trim()) return;
    
    setLoading(true);
    try {
      const result = await typedApi.search.ttx({
        text: query,
        top_k: 10,
      });
      setTtxResults(result.results || []);
    } catch (error: any) {
      toast({
        title: "Search failed",
        description: error.response?.data?.detail || error.message || "Failed to search techniques",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleFlowSearch = async () => {
    if (!query.trim()) return;
    
    setLoading(true);
    try {
      const result = await typedApi.search.flows({
        text: query,
        techniques: [],
        flow_id: undefined,
        top_k: 10,
        min_score: 0.5,
      });
      setFlowResults(result.results || []);
    } catch (error: any) {
      toast({
        title: "Search failed",
        description: error.response?.data?.detail || "Failed to search flows",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    if (activeTab === "ttx") {
      handleTtxSearch();
    } else {
      handleFlowSearch();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  const getPlatformColor = (platforms: string[]) => {
    if (!platforms || platforms.length === 0) return "text-gray-500";
    if (platforms.includes("Windows")) return "text-blue-500";
    if (platforms.includes("Linux")) return "text-green-500";
    if (platforms.includes("macOS")) return "text-purple-500";
    if (platforms.includes("Cloud")) return "text-orange-500";
    return "text-gray-500";
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Search</h1>
        <p className="text-muted-foreground">
          Find ATT&CK techniques and attack flows
        </p>
      </div>

      <Card>
        <CardContent className="p-6">
          <div className="space-y-4">
            <div className="flex gap-2">
              <button
                onClick={() => setActiveTab("ttx")}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === "ttx"
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4" />
                  Techniques (TTX)
                </div>
              </button>
              <button
                onClick={() => setActiveTab("flows")}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === "flows"
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/80"
                }`}
              >
                <div className="flex items-center gap-2">
                  <GitBranch className="h-4 w-4" />
                  Attack Flows
                </div>
              </button>
            </div>

            <div className="flex gap-2">
              <div className="relative flex-1">
                <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder={
                    activeTab === "ttx"
                      ? "Search for techniques (e.g., 'credential dumping', 'T1003')"
                      : "Search for attack flows (e.g., 'ransomware', 'APT29')"
                  }
                  className="w-full pl-10 pr-4 py-2 border rounded-md bg-background"
                />
              </div>
              <button
                onClick={handleSearch}
                disabled={!query.trim() || loading}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <SearchIcon className="h-4 w-4" />
                )}
                Search
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      )}

      {!loading && activeTab === "ttx" && ttxResults.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">
            Technique Results ({ttxResults.length})
          </h2>
          <div className="grid gap-4">
            {ttxResults.map((result) => (
              <Link
                key={result.stix_id}
                href={`/techniques/${result.external_id || result.stix_id}`}
              >
                <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center gap-2">
                          <Shield className={`h-5 w-5 ${getPlatformColor(result.platforms)}`} />
                          <h3 className="font-semibold">{result.name}</h3>
                          {result.external_id && (
                            <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-500 rounded">
                              {result.external_id}
                            </span>
                          )}
                        </div>
                        
                        {result.description && (
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {result.description}
                          </p>
                        )}
                        
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          {result.tactics && result.tactics.length > 0 && (
                            <span className="flex items-center gap-1">
                              <Tag className="h-3 w-3" />
                              {result.tactics.join(", ")}
                            </span>
                          )}
                          {result.platforms && result.platforms.length > 0 && (
                            <span className="flex items-center gap-1">
                              <FileText className="h-3 w-3" />
                              {result.platforms.join(", ")}
                            </span>
                          )}
                          <span className="flex items-center gap-1">
                            Score: {(result.score * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}

      {!loading && activeTab === "flows" && flowResults.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">
            Attack Flow Results ({flowResults.length})
          </h2>
          <div className="grid gap-4">
            {flowResults.map((flow) => (
              <Link
                key={flow.flow_id}
                href={`/flows/${flow.flow_id}`}
              >
                <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center gap-2">
                          <GitBranch className="h-5 w-5 text-purple-500" />
                          <h3 className="font-semibold">{flow.name || flow.flow_id}</h3>
                          {flow.intrusion_set && (
                            <span className="px-2 py-0.5 text-xs bg-orange-500/20 text-orange-500 rounded">
                              {flow.intrusion_set}
                            </span>
                          )}
                        </div>
                        
                        {flow.description && (
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {flow.description}
                          </p>
                        )}
                        
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Target className="h-3 w-3" />
                            {flow.technique_count || 0} techniques
                          </span>
                          <span className="flex items-center gap-1">
                            <Users className="h-3 w-3" />
                            {flow.action_count || 0} actions
                          </span>
                          <span className="flex items-center gap-1">
                            Similarity: {(flow.similarity * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                      <ChevronRight className="h-5 w-5 text-muted-foreground" />
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}

      {!loading && query && (
        (activeTab === "ttx" && ttxResults.length === 0) ||
        (activeTab === "flows" && flowResults.length === 0)
      ) && (
        <Card>
          <CardContent className="py-12 text-center">
            <SearchIcon className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">
              No results found for "{query}"
            </p>
            <p className="text-sm text-muted-foreground mt-2">
              Try different search terms or check your spelling
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}