import { Badge } from "@/components/ui/badge";
import { EntityIcon, EntityType, getEntityTypeName } from "./entity-icon";
import { ConfidenceBadge } from "./confidence-badge";
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

export interface Entity {
  id: string;
  type: EntityType;
  name: string;
  description?: string;
  external_id?: string;
  confidence?: number;
  evidence?: {
    spans?: string[];
    context?: string;
  };
}

interface EntityListProps {
  entities: Entity[];
  showConfidence?: boolean;
  linkPattern?: string; // e.g., "/techniques/{external_id}" or "/techniques/{id}"
  emptyMessage?: string;
  compact?: boolean;
  showType?: boolean;
  showEvidence?: boolean;
  className?: string;
}

export function EntityList({
  entities,
  showConfidence = false,
  linkPattern,
  emptyMessage = "No entities found",
  compact = false,
  showType = true,
  showEvidence = false,
  className = "",
}: EntityListProps) {
  if (entities.length === 0) {
    return (
      <p className={cn("text-sm text-muted-foreground", className)}>
        {emptyMessage}
      </p>
    );
  }

  const buildLink = (entity: Entity): string | null => {
    if (!linkPattern) return null;
    
    return linkPattern
      .replace("{id}", entity.id)
      .replace("{external_id}", entity.external_id || entity.id)
      .replace("{type}", entity.type);
  };

  if (compact) {
    return (
      <div className={cn("flex flex-wrap gap-2", className)}>
        {entities.map((entity) => {
          const link = buildLink(entity);
          const content = (
            <Badge
              key={entity.id}
              variant="outline"
              className={cn(
                "text-xs",
                link && "cursor-pointer hover:bg-muted"
              )}
            >
              <EntityIcon type={entity.type} size="sm" className="mr-1" />
              {entity.name}
              {entity.external_id && (
                <span className="ml-1 text-muted-foreground">
                  ({entity.external_id})
                </span>
              )}
              {showConfidence && entity.confidence && (
                <span className="ml-1">
                  • {Math.round(entity.confidence)}%
                </span>
              )}
            </Badge>
          );

          return link ? (
            <Link key={entity.id} href={link}>
              {content}
            </Link>
          ) : (
            content
          );
        })}
      </div>
    );
  }

  return (
    <div className={cn("space-y-3", className)}>
      {entities.map((entity) => {
        const link = buildLink(entity);
        
        const entityContent = (
          <div className="flex items-start gap-3">
            <EntityIcon type={entity.type} size="md" className="mt-0.5" />
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <p className={cn(
                  "font-medium",
                  link && "hover:text-blue-500 cursor-pointer"
                )}>
                  {entity.name}
                </p>
                {entity.external_id && (
                  <Badge variant="outline" className="text-xs">
                    {entity.external_id}
                  </Badge>
                )}
                {showType && (
                  <Badge variant="secondary" className="text-xs">
                    {getEntityTypeName(entity.type)}
                  </Badge>
                )}
                {showConfidence && entity.confidence && (
                  <ConfidenceBadge
                    confidence={entity.confidence}
                    size="sm"
                    showIcon={true}
                    showPercentage={true}
                  />
                )}
              </div>
              {entity.description && (
                <p className="text-xs text-muted-foreground mt-1">
                  {entity.description}
                </p>
              )}
              {showEvidence && entity.evidence?.spans && entity.evidence.spans.length > 0 && (
                <div className="mt-2 space-y-1">
                  {entity.evidence.spans.slice(0, 2).map((span, idx) => (
                    <blockquote 
                      key={idx} 
                      className="text-xs text-muted-foreground/70 italic border-l-2 border-muted pl-2"
                    >
                      "{span.substring(0, 100)}..."
                    </blockquote>
                  ))}
                </div>
              )}
            </div>
            {link && (
              <ChevronRight className="h-4 w-4 text-muted-foreground mt-0.5" />
            )}
          </div>
        );

        if (link) {
          return (
            <Link key={entity.id} href={link}>
              <div className="hover:bg-muted/50 p-2 -m-2 rounded transition-colors">
                {entityContent}
              </div>
            </Link>
          );
        }

        return <div key={entity.id}>{entityContent}</div>;
      })}
    </div>
  );
}

interface GroupedEntityListProps {
  techniques?: Entity[];
  actors?: Entity[];
  software?: Entity[];
  showConfidence?: boolean;
  compact?: boolean;
  className?: string;
}

export function GroupedEntityList({
  techniques = [],
  actors = [],
  software = [],
  showConfidence = false,
  compact = false,
  className = "",
}: GroupedEntityListProps) {
  const groups = [
    { title: "Attack Techniques", entities: techniques, linkPattern: "/techniques/{external_id}" },
    { title: "Threat Actors", entities: actors, linkPattern: null },
    { title: "Software", entities: software, linkPattern: null },
  ].filter(group => group.entities.length > 0);

  if (groups.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No entities extracted
      </p>
    );
  }

  return (
    <div className={cn("space-y-6", className)}>
      {groups.map((group) => (
        <div key={group.title}>
          <h4 className="text-sm font-medium mb-3">{group.title}</h4>
          <EntityList
            entities={group.entities}
            showConfidence={showConfidence}
            linkPattern={group.linkPattern}
            compact={compact}
            showType={false}
          />
        </div>
      ))}
    </div>
  );
}