'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { RefreshCw, CheckCircle, XCircle, AlertCircle, Activity, Database, Search, Server, HardDrive, Cpu, Clock } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  latency_ms?: number;
  error?: string;
  [key: string]: any;
}

interface SystemHealth {
  memory?: {
    available_gb: number;
    percent_used: number;
  };
  disk?: {
    available_gb: number;
    percent_used: number;
  };
  cpu?: {
    percent_used: number;
  };
}

interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  components: {
    neo4j: ComponentHealth;
    opensearch: ComponentHealth;
    redis: ComponentHealth;
    caches: ComponentHealth & {
      technique_cache?: {
        count: number;
        loaded: boolean;
      };
      actor_cache?: {
        count: number;
        loaded: boolean;
      };
    };
    system: ComponentHealth & SystemHealth;
  };
}

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    case 'degraded':
      return <AlertCircle className="h-5 w-5 text-yellow-500" />;
    case 'unhealthy':
      return <XCircle className="h-5 w-5 text-red-500" />;
    default:
      return <AlertCircle className="h-5 w-5 text-gray-400" />;
  }
};

const StatusBadge = ({ status }: { status: string }) => {
  const variants: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
    healthy: 'default',
    degraded: 'secondary',
    unhealthy: 'destructive',
    unknown: 'outline'
  };

  const colors: Record<string, string> = {
    healthy: 'bg-green-100 text-green-800',
    degraded: 'bg-yellow-100 text-yellow-800',
    unhealthy: 'bg-red-100 text-red-800',
    unknown: 'bg-gray-100 text-gray-800'
  };

  return (
    <Badge className={colors[status] || colors.unknown}>
      {status.toUpperCase()}
    </Badge>
  );
};

const ComponentIcon = ({ name }: { name: string }) => {
  const icons: Record<string, JSX.Element> = {
    neo4j: <Database className="h-5 w-5" />,
    opensearch: <Search className="h-5 w-5" />,
    redis: <Server className="h-5 w-5" />,
    caches: <HardDrive className="h-5 w-5" />,
    system: <Cpu className="h-5 w-5" />
  };
  return icons[name] || <Activity className="h-5 w-5" />;
};

export default function HealthStatusPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('http://localhost:8000/health/ready');

      if (!response.ok && response.status !== 503) {
        throw new Error(`Failed to fetch health status: ${response.statusText}`);
      }

      const data = await response.json();
      setHealth(response.status === 503 ? data.detail : data);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch health status');
      console.error('Health fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();

    if (autoRefresh) {
      const interval = setInterval(fetchHealth, 10000); // Refresh every 10 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const formatLatency = (ms?: number) => {
    if (ms === undefined) return 'N/A';
    if (ms < 100) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  const formatBytes = (gb: number) => {
    if (gb < 1) return `${(gb * 1024).toFixed(0)}MB`;
    return `${gb.toFixed(1)}GB`;
  };

  const getProgressColor = (percent: number) => {
    if (percent < 60) return 'bg-green-500';
    if (percent < 80) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  if (loading && !health) {
    return (
      <div className="container mx-auto p-6">
        <Card className="max-w-6xl mx-auto">
          <CardContent className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 animate-spin text-blue-500" />
            <span className="ml-3 text-lg">Loading health status...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">System Health Status</h1>
          <p className="text-muted-foreground mt-1">
            Monitor the health of all system components and dependencies
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <label htmlFor="auto-refresh" className="text-sm font-medium">
              Auto Refresh
            </label>
            <input
              id="auto-refresh"
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4"
            />
          </div>
          <Button onClick={fetchHealth} disabled={loading} variant="outline">
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Last Update */}
      <div className="flex items-center text-sm text-muted-foreground">
        <Clock className="h-4 w-4 mr-1" />
        Last updated: {lastRefresh.toLocaleTimeString()}
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Overall Status */}
      {health && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <StatusIcon status={health.status} />
                <CardTitle>Overall System Status</CardTitle>
              </div>
              <StatusBadge status={health.status} />
            </div>
            <CardDescription>
              Version {health.version} • {new Date(health.timestamp).toLocaleString()}
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      {/* Component Status Grid */}
      {health?.components && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Neo4j */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ComponentIcon name="neo4j" />
                  <CardTitle className="text-lg">Neo4j Database</CardTitle>
                </div>
                <StatusBadge status={health.components.neo4j.status} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Latency:</span>
                  <span className="font-mono">{formatLatency(health.components.neo4j.latency_ms)}</span>
                </div>
                {health.components.neo4j.error && (
                  <div className="text-red-600 text-xs">{health.components.neo4j.error}</div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* OpenSearch */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ComponentIcon name="opensearch" />
                  <CardTitle className="text-lg">OpenSearch</CardTitle>
                </div>
                <StatusBadge status={health.components.opensearch.status} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Latency:</span>
                  <span className="font-mono">{formatLatency(health.components.opensearch.latency_ms)}</span>
                </div>
                {health.components.opensearch.cluster_status && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Cluster:</span>
                    <Badge variant={health.components.opensearch.cluster_status === 'green' ? 'default' : 'secondary'}>
                      {health.components.opensearch.cluster_status}
                    </Badge>
                  </div>
                )}
                {health.components.opensearch.indices && (
                  <div className="pt-1 border-t">
                    <div className="text-xs text-muted-foreground mb-1">Indices:</div>
                    {Object.entries(health.components.opensearch.indices).map(([index, exists]) => (
                      <div key={index} className="flex items-center justify-between text-xs">
                        <span>{index}</span>
                        {exists ? (
                          <CheckCircle className="h-3 w-3 text-green-500" />
                        ) : (
                          <XCircle className="h-3 w-3 text-red-500" />
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Redis */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ComponentIcon name="redis" />
                  <CardTitle className="text-lg">Redis Cache</CardTitle>
                </div>
                <StatusBadge status={health.components.redis.status} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Latency:</span>
                  <span className="font-mono">{formatLatency(health.components.redis.latency_ms)}</span>
                </div>
                {health.components.redis.memory_mb !== undefined && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Memory:</span>
                    <span className="font-mono">{health.components.redis.memory_mb.toFixed(1)}MB</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Caches */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ComponentIcon name="caches" />
                  <CardTitle className="text-lg">Application Caches</CardTitle>
                </div>
                <StatusBadge status={health.components.caches.status} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                {health.components.caches.technique_cache && (
                  <div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Techniques:</span>
                      <span className="font-mono">{health.components.caches.technique_cache.count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Loaded:</span>
                      {health.components.caches.technique_cache.loaded ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                    </div>
                  </div>
                )}
                {health.components.caches.actor_cache && (
                  <div className="pt-2 border-t">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Actors:</span>
                      <span className="font-mono">{health.components.caches.actor_cache.count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Loaded:</span>
                      {health.components.caches.actor_cache.loaded ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* System Resources */}
          <Card className="md:col-span-2">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ComponentIcon name="system" />
                  <CardTitle className="text-lg">System Resources</CardTitle>
                </div>
                <StatusBadge status={health.components.system.status} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Memory */}
                {health.components.system.memory && (
                  <div>
                    <div className="flex justify-between mb-1 text-sm">
                      <span className="text-muted-foreground">Memory</span>
                      <span>
                        {formatBytes(health.components.system.memory.available_gb)} available •
                        {' '}{health.components.system.memory.percent_used.toFixed(1)}% used
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getProgressColor(health.components.system.memory.percent_used)}`}
                        style={{ width: `${health.components.system.memory.percent_used}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Disk */}
                {health.components.system.disk && (
                  <div>
                    <div className="flex justify-between mb-1 text-sm">
                      <span className="text-muted-foreground">Disk</span>
                      <span>
                        {formatBytes(health.components.system.disk.available_gb)} available •
                        {' '}{health.components.system.disk.percent_used.toFixed(1)}% used
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getProgressColor(health.components.system.disk.percent_used)}`}
                        style={{ width: `${health.components.system.disk.percent_used}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* CPU */}
                {health.components.system.cpu && (
                  <div>
                    <div className="flex justify-between mb-1 text-sm">
                      <span className="text-muted-foreground">CPU</span>
                      <span>{health.components.system.cpu.percent_used.toFixed(1)}% used</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${getProgressColor(health.components.system.cpu.percent_used)}`}
                        style={{ width: `${health.components.system.cpu.percent_used}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}