"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import {
  Target,
  Loader2,
  ChevronRight,
  AlertTriangle,
  Calendar,
  Activity,
  Users,
  GitBranch,
  FileText,
  Merge,
  Clock,
  TrendingUp,
  Shield,
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { typedApi } from "@/lib/api-client";

interface Campaign {
  id: string;
  name: string;
  description?: string;
  first_seen?: string;
  last_seen?: string;
  created: string;
  modified: string;
  x_bj_status?: string;
  attribution?: {
    intrusion_sets: string[];
  };
  uses?: {
    techniques: string[];
    software: string[];
  };
  report_count?: number;
  flow_count?: number;
}

interface CampaignStats {
  total_campaigns: number;
  provisional_campaigns: number;
  confirmed_campaigns: number;
  total_techniques: number;
  total_actors: number;
  recent_7_days: number;
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<CampaignStats | null>(null);
  const [showProvisional, setShowProvisional] = useState(true);
  const [selectedCampaigns, setSelectedCampaigns] = useState<Set<string>>(new Set());
  const [merging, setMerging] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    fetchCampaigns();
    fetchStats();
  }, [showProvisional]);

  const fetchCampaigns = async () => {
    try {
      // TODO: Use actual endpoint when backend implements /v1/campaigns
      // For now, we'll simulate with empty data
      const mockCampaigns: Campaign[] = [];
      setCampaigns(mockCampaigns);
    } catch (error) {
      console.error("Error fetching campaigns:", error);
      toast({
        title: "Error loading campaigns",
        description: "Failed to load campaigns list",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    // TODO: Get actual stats from backend
    const mockStats: CampaignStats = {
      total_campaigns: 0,
      provisional_campaigns: 0,
      confirmed_campaigns: 0,
      total_techniques: 0,
      total_actors: 0,
      recent_7_days: 0,
    };
    setStats(mockStats);
  };

  const handleMergeCampaigns = async () => {
    if (selectedCampaigns.size < 2) {
      toast({
        title: "Select Campaigns",
        description: "Please select at least 2 campaigns to merge",
        variant: "destructive",
      });
      return;
    }

    setMerging(true);
    try {
      const result = await typedApi.campaigns.merge({
        from_ids: Array.from(selectedCampaigns),
      });

      toast({
        title: "Campaigns Merged",
        description: `Successfully merged ${selectedCampaigns.size} campaigns`,
      });

      setSelectedCampaigns(new Set());
      fetchCampaigns();
      fetchStats();
    } catch (error: any) {
      console.error("Error merging campaigns:", error);
      toast({
        title: "Merge Failed",
        description: error.response?.data?.detail || "Failed to merge campaigns",
        variant: "destructive",
      });
    } finally {
      setMerging(false);
    }
  };

  const getDurationString = (firstSeen?: string, lastSeen?: string) => {
    if (!firstSeen || !lastSeen) return "Unknown duration";
    const start = new Date(firstSeen);
    const end = new Date(lastSeen);
    const days = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    return `${days} days`;
  };

  const filteredCampaigns = campaigns.filter((campaign) => {
    if (!showProvisional && campaign.x_bj_status === "provisional") {
      return false;
    }
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Campaigns</h1>
          <p className="text-muted-foreground">
            Coordinated threat activity extracted from reports
          </p>
        </div>
        {selectedCampaigns.size > 0 && (
          <button
            onClick={handleMergeCampaigns}
            disabled={merging || selectedCampaigns.size < 2}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {merging ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Merging...
              </>
            ) : (
              <>
                <Merge className="h-4 w-4" />
                Merge {selectedCampaigns.size} Campaigns
              </>
            )}
          </button>
        )}
      </div>

      {stats && (
        <div className="grid gap-4 md:grid-cols-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_campaigns}</div>
              <p className="text-xs text-muted-foreground">
                All campaigns
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Confirmed</CardTitle>
              <Shield className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.confirmed_campaigns}</div>
              <p className="text-xs text-muted-foreground">
                Validated
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Provisional</CardTitle>
              <Clock className="h-4 w-4 text-yellow-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.provisional_campaigns}</div>
              <p className="text-xs text-muted-foreground">
                Pending review
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Techniques</CardTitle>
              <Activity className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_techniques}</div>
              <p className="text-xs text-muted-foreground">
                Unique TTPs
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Actors</CardTitle>
              <Users className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_actors}</div>
              <p className="text-xs text-muted-foreground">
                Threat actors
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Recent</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.recent_7_days}</div>
              <p className="text-xs text-muted-foreground">
                Last 7 days
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Campaign Library</CardTitle>
              <CardDescription>
                Coordinated threat activities identified from reports
              </CardDescription>
            </div>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={showProvisional}
                onChange={(e) => setShowProvisional(e.target.checked)}
                className="rounded"
              />
              <span className="text-sm">Show provisional campaigns</span>
            </label>
          </div>
        </CardHeader>
        <CardContent>
          {filteredCampaigns.length === 0 ? (
            <div className="text-center py-12">
              <Target className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-lg font-medium">No campaigns found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {campaigns.length === 0 
                  ? "Campaigns are created when reports meet the rubric criteria"
                  : "No campaigns match your current filters"}
              </p>
              <Link href="/reports/new">
                <button className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
                  Ingest Report
                </button>
              </Link>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredCampaigns.map((campaign) => (
                <div key={campaign.id} className="flex items-start gap-4">
                  <input
                    type="checkbox"
                    checked={selectedCampaigns.has(campaign.id)}
                    onChange={(e) => {
                      const newSelected = new Set(selectedCampaigns);
                      if (e.target.checked) {
                        newSelected.add(campaign.id);
                      } else {
                        newSelected.delete(campaign.id);
                      }
                      setSelectedCampaigns(newSelected);
                    }}
                    className="mt-5"
                  />
                  <Link 
                    href={`/campaigns/${encodeURIComponent(campaign.id)}`}
                    className="flex-1"
                  >
                    <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                      <CardHeader>
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <Target className="h-5 w-5 text-orange-500" />
                              <CardTitle className="text-lg">{campaign.name}</CardTitle>
                              {campaign.x_bj_status === "provisional" && (
                                <Badge variant="outline" className="text-yellow-600 border-yellow-600">
                                  Provisional
                                </Badge>
                              )}
                            </div>
                            {campaign.description && (
                              <CardDescription className="mt-2">
                                {campaign.description}
                              </CardDescription>
                            )}
                          </div>
                          <ChevronRight className="h-5 w-5 text-muted-foreground" />
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="flex items-center gap-6 text-sm text-muted-foreground">
                          {campaign.first_seen && campaign.last_seen && (
                            <span className="flex items-center gap-1">
                              <Calendar className="h-4 w-4" />
                              {format(new Date(campaign.first_seen), "MMM yyyy")} - {format(new Date(campaign.last_seen), "MMM yyyy")}
                              <span className="text-xs ml-1">({getDurationString(campaign.first_seen, campaign.last_seen)})</span>
                            </span>
                          )}
                          {campaign.attribution?.intrusion_sets && campaign.attribution.intrusion_sets.length > 0 && (
                            <span className="flex items-center gap-1">
                              <Users className="h-4 w-4" />
                              {campaign.attribution.intrusion_sets.length} actor(s)
                            </span>
                          )}
                          {campaign.uses?.techniques && campaign.uses.techniques.length > 0 && (
                            <span className="flex items-center gap-1">
                              <Activity className="h-4 w-4" />
                              {campaign.uses.techniques.length} techniques
                            </span>
                          )}
                          {campaign.report_count !== undefined && campaign.report_count > 0 && (
                            <span className="flex items-center gap-1">
                              <FileText className="h-4 w-4" />
                              {campaign.report_count} reports
                            </span>
                          )}
                          {campaign.flow_count !== undefined && campaign.flow_count > 0 && (
                            <span className="flex items-center gap-1">
                              <GitBranch className="h-4 w-4" />
                              {campaign.flow_count} flows
                            </span>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </Link>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {stats && stats.provisional_campaigns > 0 && (
        <Card className="bg-yellow-500/10 border-yellow-500/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-500" />
              Provisional Campaigns
            </CardTitle>
            <CardDescription>
              {stats.provisional_campaigns} campaigns need review for consolidation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Provisional campaigns are created when reports partially meet the rubric criteria.
              Review and merge related provisional campaigns to create confirmed campaigns with
              stronger attribution and timeline evidence.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}