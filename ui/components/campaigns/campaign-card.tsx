import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Target, 
  Calendar, 
  Users, 
  Activity, 
  FileText, 
  GitBranch, 
  ChevronRight,
  Clock,
  Merge
} from "lucide-react";
import Link from "next/link";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

export interface CampaignData {
  id: string;
  name: string;
  description?: string;
  first_seen?: string;
  last_seen?: string;
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

interface CampaignCardProps {
  campaign: CampaignData;
  selectable?: boolean;
  selected?: boolean;
  onSelect?: (id: string) => void;
  onClick?: () => void;
  showActions?: boolean;
  showStats?: boolean;
  compact?: boolean;
  className?: string;
}

export function CampaignCard({
  campaign,
  selectable = false,
  selected = false,
  onSelect,
  onClick,
  showActions = false,
  showStats = true,
  compact = false,
  className = "",
}: CampaignCardProps) {
  const getDurationString = (firstSeen?: string, lastSeen?: string) => {
    if (!firstSeen || !lastSeen) return "Unknown duration";
    const start = new Date(firstSeen);
    const end = new Date(lastSeen);
    const days = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    
    if (days < 30) return `${days} days`;
    if (days < 365) return `${Math.round(days / 30)} months`;
    return `${Math.round(days / 365)} years`;
  };

  const handleCardClick = (e: React.MouseEvent) => {
    if (onClick) {
      onClick();
    }
  };

  const handleSelectChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.stopPropagation();
    if (onSelect) {
      onSelect(campaign.id);
    }
  };

  if (compact) {
    return (
      <div 
        className={cn(
          "flex items-center gap-3 p-3 border rounded-lg",
          onClick && "cursor-pointer hover:bg-muted/50",
          selected && "bg-muted/30 border-primary",
          className
        )}
        onClick={handleCardClick}
      >
        {selectable && (
          <input
            type="checkbox"
            checked={selected}
            onChange={handleSelectChange}
            onClick={(e) => e.stopPropagation()}
            className="rounded"
          />
        )}
        <Target className="h-4 w-4 text-orange-500" />
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <p className="font-medium text-sm">{campaign.name}</p>
            {campaign.x_bj_status === "provisional" && (
              <Badge variant="outline" className="text-xs text-yellow-600 border-yellow-600">
                Provisional
              </Badge>
            )}
          </div>
          {campaign.first_seen && campaign.last_seen && (
            <p className="text-xs text-muted-foreground">
              {format(new Date(campaign.first_seen), "MMM yyyy")} - {format(new Date(campaign.last_seen), "MMM yyyy")}
            </p>
          )}
        </div>
        {showStats && (
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            {campaign.uses?.techniques && (
              <span>{campaign.uses.techniques.length} TTPs</span>
            )}
            {campaign.attribution?.intrusion_sets && campaign.attribution.intrusion_sets.length > 0 && (
              <span>{campaign.attribution.intrusion_sets.length} actors</span>
            )}
          </div>
        )}
        <ChevronRight className="h-4 w-4 text-muted-foreground" />
      </div>
    );
  }

  return (
    <Card 
      className={cn(
        onClick && "cursor-pointer hover:bg-muted/50 transition-colors",
        selected && "ring-2 ring-primary",
        className
      )}
      onClick={handleCardClick}
    >
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2">
              {selectable && (
                <input
                  type="checkbox"
                  checked={selected}
                  onChange={handleSelectChange}
                  onClick={(e) => e.stopPropagation()}
                  className="rounded mr-2"
                />
              )}
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
          {showActions ? (
            <div className="flex items-center gap-2">
              <Link href={`/campaigns/${campaign.id}`} onClick={(e) => e.stopPropagation()}>
                <button className="p-2 hover:bg-muted rounded-md" title="View Details">
                  <ChevronRight className="h-4 w-4" />
                </button>
              </Link>
              {campaign.x_bj_status === "provisional" && (
                <button 
                  className="p-2 hover:bg-muted rounded-md" 
                  title="Merge Campaign"
                  onClick={(e) => {
                    e.stopPropagation();
                    // Handle merge action
                  }}
                >
                  <Merge className="h-4 w-4" />
                </button>
              )}
            </div>
          ) : (
            <ChevronRight className="h-5 w-5 text-muted-foreground" />
          )}
        </div>
      </CardHeader>
      {showStats && (
        <CardContent>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            {campaign.first_seen && campaign.last_seen && (
              <span className="flex items-center gap-1">
                <Calendar className="h-4 w-4" />
                {format(new Date(campaign.first_seen), "MMM yyyy")} - {format(new Date(campaign.last_seen), "MMM yyyy")}
                <span className="text-xs ml-1">
                  ({getDurationString(campaign.first_seen, campaign.last_seen)})
                </span>
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
      )}
    </Card>
  );
}

interface CampaignListProps {
  campaigns: CampaignData[];
  selectable?: boolean;
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
  onCampaignClick?: (campaign: CampaignData) => void;
  showActions?: boolean;
  compact?: boolean;
  emptyMessage?: string;
  className?: string;
}

export function CampaignList({
  campaigns,
  selectable = false,
  selectedIds = new Set(),
  onSelectionChange,
  onCampaignClick,
  showActions = false,
  compact = false,
  emptyMessage = "No campaigns found",
  className = "",
}: CampaignListProps) {
  if (campaigns.length === 0) {
    return (
      <div className="text-center py-12">
        <Target className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <p className="text-lg font-medium">{emptyMessage}</p>
      </div>
    );
  }

  const handleSelect = (id: string) => {
    if (!onSelectionChange) return;
    
    const newSelection = new Set(selectedIds);
    if (selectedIds.has(id)) {
      newSelection.delete(id);
    } else {
      newSelection.add(id);
    }
    onSelectionChange(newSelection);
  };

  return (
    <div className={cn("space-y-4", className)}>
      {campaigns.map((campaign) => (
        <CampaignCard
          key={campaign.id}
          campaign={campaign}
          selectable={selectable}
          selected={selectedIds.has(campaign.id)}
          onSelect={handleSelect}
          onClick={onCampaignClick ? () => onCampaignClick(campaign) : undefined}
          showActions={showActions}
          compact={compact}
        />
      ))}
    </div>
  );
}