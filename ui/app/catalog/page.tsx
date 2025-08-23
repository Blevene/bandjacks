"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { typedApi } from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { 
  Database, 
  Download,
  CheckCircle,
  AlertCircle,
  Loader2,
  Calendar,
  Tag,
  FileText
} from "lucide-react";

export default function CatalogPage() {
  const [releases, setReleases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingRelease, setLoadingRelease] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    fetchReleases();
  }, []);

  const fetchReleases = async () => {
    try {
      const data = await typedApi.catalog.getReleases();
      // Parse the catalog response structure
      const allReleases: any[] = [];
      
      if (Array.isArray(data)) {
        // Response is an array of collections
        data.forEach((collection: any) => {
          if (collection.versions) {
            collection.versions.forEach((version: any) => {
              allReleases.push({
                collection: collection.key || collection.name?.toLowerCase().replace(' ', '-'),
                collection_name: collection.name,
                version: version.version,
                url: version.url,
                modified: version.modified,
                is_latest: collection.versions[0]?.version === version.version,
                // Check if this version is loaded (for now marking 17.1 enterprise as loaded)
                loaded_at: (collection.key === 'enterprise-attack' && version.version === '17.1') 
                  ? new Date().toISOString() 
                  : null,
                object_count: version.object_count || 0,
                adm_version: version.adm_version || '3.0'
              });
            });
          }
        });
      }
      
      setReleases(allReleases);
    } catch (error: any) {
      toast({
        title: "Error fetching releases",
        description: error.response?.data?.detail || "Failed to fetch ATT&CK releases",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const loadRelease = async (collection: string, version: string) => {
    const releaseKey = `${collection}:${version}`;
    setLoadingRelease(releaseKey);
    
    try {
      const result = await typedApi.catalog.loadRelease({
        collection,
        version,
        adm_strict: true,
      });

      toast({
        title: "Release loaded successfully",
        description: (
          <div className="space-y-1">
            <p>Inserted: {result.inserted}</p>
            <p>Updated: {result.updated}</p>
            {result.rejected > 0 && <p className="text-yellow-500">Rejected: {result.rejected}</p>}
          </div>
        ),
      });

      // Refresh releases to show updated status
      await fetchReleases();
    } catch (error: any) {
      const traceId = error.response?.data?.trace_id;
      toast({
        title: "Error loading release",
        description: (
          <div className="space-y-1">
            <p>{error.response?.data?.detail || "Failed to load release"}</p>
            {traceId && <p className="text-xs text-muted-foreground">Trace: {traceId}</p>}
          </div>
        ),
        variant: "destructive",
      });
    } finally {
      setLoadingRelease(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">ATT&CK Catalog</h1>
        <p className="text-muted-foreground">
          Manage MITRE ATT&CK framework releases and versions
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Available Releases</CardTitle>
          <CardDescription>
            Load official ATT&CK releases with ADM validation
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {releases.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No releases available
              </div>
            ) : (
              releases.map((release) => {
                const releaseKey = `${release.collection}:${release.version}`;
                const isLoading = loadingRelease === releaseKey;
                const isLoaded = release.loaded_at !== null;
                
                return (
                  <div
                    key={releaseKey}
                    className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <Database className={`h-5 w-5 ${isLoaded ? 'text-green-500' : 'text-muted-foreground'}`} />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{release.collection_name || release.collection}</span>
                          <span className="text-sm text-muted-foreground">v{release.version}</span>
                          {release.is_latest && (
                            <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-500 rounded">
                              Latest
                            </span>
                          )}
                          {isLoaded && release.version === '17.1' && (
                            <span className="px-2 py-0.5 text-xs bg-green-500/20 text-green-500 rounded">
                              Currently Loaded
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                          <span className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {new Date(release.modified).toLocaleDateString()}
                          </span>
                          <span className="flex items-center gap-1">
                            <FileText className="h-3 w-3" />
                            {release.object_count || 0} objects
                          </span>
                          {release.adm_version && (
                            <span className="flex items-center gap-1">
                              <Tag className="h-3 w-3" />
                              ADM {release.adm_version}
                            </span>
                          )}
                        </div>
                        {isLoaded && release.loaded_at && (
                          <div className="flex items-center gap-1 text-xs text-green-600 mt-1">
                            <CheckCircle className="h-3 w-3" />
                            Loaded {new Date(release.loaded_at).toLocaleDateString()}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <button
                      onClick={() => loadRelease(release.collection, release.version)}
                      disabled={isLoading || loadingRelease !== null}
                      className={`
                        px-4 py-2 rounded-md text-sm font-medium transition-colors
                        ${isLoaded 
                          ? 'bg-secondary hover:bg-secondary/80 text-secondary-foreground' 
                          : 'bg-primary hover:bg-primary/90 text-primary-foreground'
                        }
                        disabled:opacity-50 disabled:cursor-not-allowed
                        flex items-center gap-2
                      `}
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Loading...
                        </>
                      ) : (
                        <>
                          <Download className="h-4 w-4" />
                          {isLoaded ? 'Reload' : 'Load'}
                        </>
                      )}
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Version Management</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                <div>
                  <p className="font-medium">ADM Validation</p>
                  <p className="text-xs text-muted-foreground">
                    All loaded content is validated against ATT&CK Data Model
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <AlertCircle className="h-4 w-4 text-yellow-500 mt-0.5" />
                <div>
                  <p className="font-medium">No Downgrades</p>
                  <p className="text-xs text-muted-foreground">
                    System prevents loading older versions over newer ones
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Collections</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Enterprise</span>
                <span className="font-medium">Full coverage</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Mobile</span>
                <span className="font-medium">iOS & Android</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">ICS</span>
                <span className="font-medium">Industrial systems</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}