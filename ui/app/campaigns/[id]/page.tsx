"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useParams, useRouter } from "next/navigation";
import {
  Target,
  Loader2,
  AlertTriangle,
  Calendar,
  Activity,
  Users,
  GitBranch,
  FileText,
  Shield,
  Package,
  ChevronRight,
  Clock,
  Link as LinkIcon,
  Merge,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { typedApi } from "@/lib/api-client";

interface CampaignDetail {
  id: string;
  type: string;
  spec_version: string;
  name: string;
  description?: string;
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
  created: string;
  modified: string;
  x_bj_status?: string;
  relationships?: {
    attributed_to: RelatedEntity[];
    uses_techniques: RelatedEntity[];
    uses_software: RelatedEntity[];
    has_flows: RelatedEntity[];
    described_by: RelatedEntity[];
  };
}

interface RelatedEntity {
  id: string;
  type: string;
  name: string;
  description?: string;
  external_id?: string;
  confidence?: number;
  first_seen?: string;
  last_seen?: string;
}

export default function CampaignDetailPage() {
  const params = useParams();
  const router = useRouter();
  const campaignId = params.id as string;
  const [campaign, setCampaign] = useState<CampaignDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"overview" | "timeline" | "relationships">("overview");
  const { toast } = useToast();

  useEffect(() => {
    if (campaignId) {
      fetchCampaign();
    }
  }, [campaignId]);

  const fetchCampaign = async () => {
    try {
      // TODO: Use actual endpoint when backend implements /v1/campaigns/{id}
      // For now, we'll simulate with a 404
      const data = await typedApi.campaigns.get(campaignId);
      setCampaign(data);
    } catch (error: any) {
      console.error("Error fetching campaign:", error);
      
      // For now, show a message that campaigns are being implemented
      if (error.response?.status === 404 || error.response?.status === 500) {
        toast({
          title: "Campaign endpoint not implemented",
          description: "Backend campaign details endpoint is pending implementation",
        });
      } else {
        toast({
          title: "Error loading campaign",
          description: error.response?.data?.detail || "Failed to load campaign details",
          variant: "destructive",
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleMergeWithOthers = () => {
    router.push(`/campaigns?merge=${campaignId}`);
  };

  const getDurationString = (firstSeen?: string, lastSeen?: string) => {
    if (!firstSeen || !lastSeen) return "Unknown duration";
    const start = new Date(firstSeen);
    const end = new Date(lastSeen);
    const days = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    
    if (days < 30) return `${days} days`;
    if (days < 365) return `${Math.round(days / 30)} months`;
    return `${Math.round(days / 365)} years`;
  };

  const getEntityIcon = (type: string) => {
    switch (type) {
      case "attack-pattern":
        return <Shield className="h-4 w-4 text-blue-500" />;
      case "intrusion-set":
        return <Users className="h-4 w-4 text-red-500" />;
      case "tool":
      case "malware":
        return <Package className="h-4 w-4 text-purple-500" />;
      case "attack-flow":
        return <GitBranch className="h-4 w-4 text-green-500" />;
      case "report":
        return <FileText className="h-4 w-4 text-gray-500" />;
      default:
        return <Activity className="h-4 w-4 text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="text-center py-12">
        <Target className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <p className="text-lg font-medium">Campaign details coming soon</p>
        <p className="text-sm text-muted-foreground mt-2">
          The campaign details endpoint is pending backend implementation
        </p>
        <Link href="/campaigns">
          <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
            Back to Campaigns
          </button>
        </Link>
      </div>
    );
  }

  const techniques = campaign.relationships?.uses_techniques || [];
  const actors = campaign.relationships?.attributed_to || [];
  const software = campaign.relationships?.uses_software || [];
  const flows = campaign.relationships?.has_flows || [];
  const reports = campaign.relationships?.described_by || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
            <Link href="/campaigns" className="hover:text-foreground">
              Campaigns
            </Link>
            <ChevronRight className="h-4 w-4" />
            <span className="text-foreground">{campaign.name}</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Target className="h-8 w-8 text-orange-500" />
            {campaign.name}
            {campaign.x_bj_status === "provisional" && (
              <Badge variant="outline" className="text-yellow-600 border-yellow-600">
                Provisional
              </Badge>
            )}
          </h1>
          {campaign.description && (
            <p className="text-muted-foreground mt-2">{campaign.description}</p>
          )}
        </div>
        {campaign.x_bj_status === "provisional" && (
          <button
            onClick={handleMergeWithOthers}
            className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-muted"
          >
            <Merge className="h-4 w-4" />
            Merge Campaign
          </button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Duration</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold">
              {getDurationString(campaign.first_seen, campaign.last_seen)}
            </div>
            <p className="text-xs text-muted-foreground">
              Campaign timeline
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attribution</CardTitle>
            <Users className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{actors.length}</div>
            <p className="text-xs text-muted-foreground">
              Threat actors
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Techniques</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{techniques.length}</div>
            <p className="text-xs text-muted-foreground">
              TTPs used
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Tools</CardTitle>
            <Package className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{software.length}</div>
            <p className="text-xs text-muted-foreground">
              Software used
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Reports</CardTitle>
            <FileText className="h-4 w-4 text-gray-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{reports.length}</div>
            <p className="text-xs text-muted-foreground">
              Source reports
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "overview"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab("timeline")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "timeline"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Timeline
        </button>
        <button
          onClick={() => setActiveTab("relationships")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "relationships"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Relationships
        </button>
      </div>

      {activeTab === "overview" && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Campaign Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-sm font-medium text-muted-foreground">First Seen</p>
                <p className="text-sm">
                  {campaign.first_seen 
                    ? format(new Date(campaign.first_seen), "MMMM d, yyyy")
                    : "Unknown"}
                </p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Last Seen</p>
                <p className="text-sm">
                  {campaign.last_seen 
                    ? format(new Date(campaign.last_seen), "MMMM d, yyyy")
                    : "Unknown"}
                </p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Status</p>
                <p className="text-sm">
                  {campaign.x_bj_status === "provisional" ? "Provisional (needs review)" : "Confirmed"}
                </p>
              </div>
              {campaign.aliases && campaign.aliases.length > 0 && (
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Aliases</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {campaign.aliases.map((alias, idx) => (
                      <Badge key={idx} variant="secondary" className="text-xs">
                        {alias}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Attribution</CardTitle>
              <CardDescription>
                Threat actors linked to this campaign
              </CardDescription>
            </CardHeader>
            <CardContent>
              {actors.length === 0 ? (
                <p className="text-sm text-muted-foreground">No attribution available</p>
              ) : (
                <div className="space-y-3">
                  {actors.map((actor) => (
                    <div key={actor.id} className="flex items-start gap-3">
                      <Users className="h-5 w-5 text-red-500 mt-0.5" />
                      <div className="flex-1">
                        <p className="font-medium">{actor.name}</p>
                        {actor.description && (
                          <p className="text-xs text-muted-foreground mt-1">
                            {actor.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Attack Flows</CardTitle>
              <CardDescription>
                Sequenced attack patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              {flows.length === 0 ? (
                <p className="text-sm text-muted-foreground">No attack flows generated</p>
              ) : (
                <div className="space-y-3">
                  {flows.map((flow) => (
                    <Link key={flow.id} href={`/flows/${flow.id}`}>
                      <div className="flex items-start gap-3 hover:bg-muted/50 p-2 rounded cursor-pointer">
                        <GitBranch className="h-5 w-5 text-green-500 mt-0.5" />
                        <div className="flex-1">
                          <p className="font-medium text-sm">{flow.name}</p>
                          {flow.description && (
                            <p className="text-xs text-muted-foreground mt-1">
                              {flow.description}
                            </p>
                          )}
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground mt-0.5" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Source Reports</CardTitle>
              <CardDescription>
                Reports that describe this campaign
              </CardDescription>
            </CardHeader>
            <CardContent>
              {reports.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked reports</p>
              ) : (
                <div className="space-y-3">
                  {reports.map((report) => (
                    <Link key={report.id} href={`/reports/${report.id}`}>
                      <div className="flex items-start gap-3 hover:bg-muted/50 p-2 rounded cursor-pointer">
                        <FileText className="h-5 w-5 text-gray-500 mt-0.5" />
                        <div className="flex-1">
                          <p className="font-medium text-sm">{report.name}</p>
                          {report.description && (
                            <p className="text-xs text-muted-foreground mt-1">
                              {report.description}
                            </p>
                          )}
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground mt-0.5" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === "timeline" && (
        <Card>
          <CardHeader>
            <CardTitle>Campaign Timeline</CardTitle>
            <CardDescription>
              Temporal view of campaign activity
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {campaign.first_seen && (
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-green-500 mt-2"></div>
                  <div>
                    <p className="font-medium">Campaign Start</p>
                    <p className="text-sm text-muted-foreground">
                      {format(new Date(campaign.first_seen), "MMMM d, yyyy")}
                    </p>
                  </div>
                </div>
              )}
              
              {techniques.filter(t => t.first_seen).map((technique) => (
                <div key={technique.id} className="flex items-start gap-3 ml-1 border-l-2 border-muted pl-2">
                  <Shield className="h-4 w-4 text-blue-500 mt-1" />
                  <div>
                    <p className="font-medium text-sm">{technique.name}</p>
                    {technique.first_seen && (
                      <p className="text-xs text-muted-foreground">
                        {format(new Date(technique.first_seen), "MMMM d, yyyy")}
                      </p>
                    )}
                  </div>
                </div>
              ))}
              
              {campaign.last_seen && (
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500 mt-2"></div>
                  <div>
                    <p className="font-medium">Campaign End</p>
                    <p className="text-sm text-muted-foreground">
                      {format(new Date(campaign.last_seen), "MMMM d, yyyy")}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "relationships" && (
        <div className="grid gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Techniques Used</CardTitle>
              <CardDescription>
                {techniques.length} ATT&CK techniques employed in this campaign
              </CardDescription>
            </CardHeader>
            <CardContent>
              {techniques.length === 0 ? (
                <p className="text-sm text-muted-foreground">No techniques identified</p>
              ) : (
                <div className="grid gap-3 md:grid-cols-2">
                  {techniques.map((technique) => (
                    <div key={technique.id} className="flex items-start gap-3">
                      <Shield className="h-5 w-5 text-blue-500 mt-0.5" />
                      <div className="flex-1">
                        <Link href={`/techniques/${technique.external_id || technique.id}`}>
                          <p className="font-medium text-sm hover:text-blue-500 cursor-pointer">
                            {technique.name}
                          </p>
                        </Link>
                        {technique.external_id && (
                          <Badge variant="outline" className="text-xs mt-1">
                            {technique.external_id}
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Software & Tools</CardTitle>
              <CardDescription>
                {software.length} tools and malware used in this campaign
              </CardDescription>
            </CardHeader>
            <CardContent>
              {software.length === 0 ? (
                <p className="text-sm text-muted-foreground">No software identified</p>
              ) : (
                <div className="grid gap-3 md:grid-cols-2">
                  {software.map((tool) => (
                    <div key={tool.id} className="flex items-start gap-3">
                      <Package className="h-5 w-5 text-purple-500 mt-0.5" />
                      <div className="flex-1">
                        <p className="font-medium text-sm">{tool.name}</p>
                        <Badge variant="outline" className="text-xs mt-1">
                          {tool.type === "malware" ? "Malware" : "Tool"}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <Card className="bg-muted/30">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Campaign ID: {campaign.id}</span>
            <span>STIX {campaign.spec_version}</span>
            <span>Modified: {format(new Date(campaign.modified), "MMM d, yyyy HH:mm")}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}