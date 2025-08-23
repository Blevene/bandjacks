import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  Database, 
  GitBranch,
  Search,
  Shield,
  TrendingUp
} from "lucide-react";

// Mock data for now - will be fetched from API
const mockMetrics = {
  bundles_ingested: 1247,
  objects_rejected: 23,
  search_p95: 287,
  flows_built_total: 156,
  overlay_calls_total: 892,
  uncertainty_queue_size: 47,
  coverage_gap_rate: 32.5,
  techniques_covered: 418,
};

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your threat intelligence platform
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Bundles Ingested
            </CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {mockMetrics.bundles_ingested.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">
              {mockMetrics.objects_rejected} objects rejected
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Search Performance
            </CardTitle>
            <Search className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockMetrics.search_p95}ms</div>
            <p className="text-xs text-muted-foreground">
              P95 response time
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Attack Flows
            </CardTitle>
            <GitBranch className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockMetrics.flows_built_total}</div>
            <p className="text-xs text-muted-foreground">
              {mockMetrics.overlay_calls_total} overlay calls
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Review Queue
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mockMetrics.uncertainty_queue_size}</div>
            <p className="text-xs text-muted-foreground">
              Items pending review
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Coverage Overview</CardTitle>
            <CardDescription>
              Technique coverage across all platforms
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-500" />
                  <span className="text-sm font-medium">Techniques Covered</span>
                </div>
                <span className="text-2xl font-bold">{mockMetrics.techniques_covered}</span>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>Coverage Rate</span>
                  <span className="font-medium">
                    {(100 - mockMetrics.coverage_gap_rate).toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div 
                    className="bg-green-500 h-2 rounded-full transition-all"
                    style={{ width: `${100 - mockMetrics.coverage_gap_rate}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 pt-4">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Windows</p>
                  <p className="text-xl font-bold">89%</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Linux</p>
                  <p className="text-xl font-bold">72%</p>
                </div>
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Cloud</p>
                  <p className="text-xl font-bold">64%</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>
              API health and service status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">API Backend</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Healthy</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">Neo4j Database</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Connected</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  <span className="text-sm">OpenSearch</span>
                </div>
                <span className="text-xs text-green-500 font-medium">Operational</span>
              </div>
              
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm">LLM Service</span>
                </div>
                <span className="text-xs text-yellow-500 font-medium">Rate Limited</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>
            Latest operations and events
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0">
                <Database className="h-5 w-5 text-blue-500" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium">ATT&CK v14.1 loaded</p>
                <p className="text-xs text-muted-foreground">2 hours ago</p>
              </div>
              <span className="text-xs text-green-500">Success</span>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0">
                <GitBranch className="h-5 w-5 text-purple-500" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium">Attack flow generated for APT29</p>
                <p className="text-xs text-muted-foreground">3 hours ago</p>
              </div>
              <span className="text-xs text-green-500">Completed</span>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0">
                <Shield className="h-5 w-5 text-orange-500" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium">15 Sigma rules linked to analytics</p>
                <p className="text-xs text-muted-foreground">5 hours ago</p>
              </div>
              <span className="text-xs text-blue-500">Processed</span>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium">Bundle validation failed: 3 objects rejected</p>
                <p className="text-xs text-muted-foreground">6 hours ago</p>
              </div>
              <span className="text-xs text-yellow-500">Warning</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
