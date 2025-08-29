"use client";

import { useState, useEffect, useCallback } from "react";
import { Search, Loader2, CheckCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { apiClient } from "@/lib/api-client";
import { useDebounce } from "@/hooks/use-debounce";
import { InputExamples } from "./input-examples";
import { isValidTechniqueId, isValidGroupId, formatTechniqueId } from "@/lib/validators";

// Mock search results for development
function getMockSearchResults(query: string, type: 'technique' | 'group'): TechniqueResult[] {
  const lowerQuery = query.toLowerCase();
  
  if (type === 'technique') {
    const mockTechniques: TechniqueResult[] = [
      {
        stix_id: "attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670",
        external_id: "T1055",
        name: "Process Injection",
        description: "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        score: 0.95,
        confidence: 0.8
      },
      {
        stix_id: "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
        external_id: "T1003",
        name: "OS Credential Dumping",
        description: "Adversaries may attempt to dump credentials to obtain account login and password information, normally in the form of a hash or a clear text password.",
        score: 0.87,
        confidence: 0.9
      },
      {
        stix_id: "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
        external_id: "T1078",
        name: "Valid Accounts",
        description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion.",
        score: 0.75,
        confidence: 0.85
      },
      {
        stix_id: "attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9",
        external_id: "T1053",
        name: "Scheduled Task/Job",
        description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        score: 0.72,
        confidence: 0.7
      },
      {
        stix_id: "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
        external_id: "T1027",
        name: "Obfuscated Files or Information",
        description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
        score: 0.68,
        confidence: 0.75
      }
    ];

    return mockTechniques.filter(tech => 
      tech.name.toLowerCase().includes(lowerQuery) || 
      tech.description.toLowerCase().includes(lowerQuery) ||
      lowerQuery.includes('injection') && tech.external_id === 'T1055' ||
      lowerQuery.includes('credential') && tech.external_id === 'T1003' ||
      lowerQuery.includes('persistence') && tech.external_id === 'T1078' ||
      lowerQuery.includes('task') && tech.external_id === 'T1053' ||
      lowerQuery.includes('obfusc') && tech.external_id === 'T1027'
    ).slice(0, 5);
  } else {
    const mockGroups: TechniqueResult[] = [
      {
        stix_id: "intrusion-set--a0cb9370-e39b-44d5-9f50-ef78e412b973",
        external_id: "G0001",
        name: "Axiom",
        description: "Axiom is a Chinese cyber espionage group that has been active since at least 2009 and has targeted a variety of industries.",
        score: 0.92,
        confidence: 0.85
      },
      {
        stix_id: "intrusion-set--fe8796a4-2a02-41a7-9bd9-3f58a8c75615",
        external_id: "G0007",
        name: "APT1",
        description: "APT1 is a Chinese threat group that has been attributed to the 2nd Bureau of the People's Liberation Army (PLA) General Staff Department's (GSD) 3rd Department.",
        score: 0.88,
        confidence: 0.9
      },
      {
        stix_id: "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
        external_id: "G0016",
        name: "APT29",
        description: "APT29 is threat group that has been attributed to Russia's SVR and has operated since at least 2008.",
        score: 0.84,
        confidence: 0.95
      },
      {
        stix_id: "intrusion-set--c93fccb1-e8e8-42cf-ae33-2ad1d183913a",
        external_id: "G0028",
        name: "Lazarus Group",
        description: "Lazarus Group is a North Korean state-sponsored cyber threat group that has been attributed to the Reconnaissance General Bureau.",
        score: 0.91,
        confidence: 0.88
      },
      {
        stix_id: "intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc",
        external_id: "G0046",
        name: "FIN7",
        description: "FIN7 is a financially-motivated threat group that has been active since 2013 primarily targeting the U.S. retail, restaurant, and hospitality sectors.",
        score: 0.79,
        confidence: 0.82
      }
    ];

    return mockGroups.filter(group => 
      group.name.toLowerCase().includes(lowerQuery) || 
      group.description.toLowerCase().includes(lowerQuery) ||
      lowerQuery.includes('chinese') && ['G0001', 'G0007'].includes(group.external_id) ||
      lowerQuery.includes('russian') && group.external_id === 'G0016' ||
      lowerQuery.includes('north korean') && group.external_id === 'G0028' ||
      lowerQuery.includes('financial') && group.external_id === 'G0046'
    ).slice(0, 5);
  }
}

interface TechniqueResult {
  stix_id: string;
  external_id: string;
  name: string;
  description: string;
  score: number;
  confidence: number;
}

interface IntelligentTechniqueInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  type?: 'technique' | 'group';
}

export function IntelligentTechniqueInput({
  value,
  onChange,
  placeholder = "Type technique name or ID (e.g., 'process injection' or 'T1055')",
  disabled = false,
  className,
  type = 'technique',
}: IntelligentTechniqueInputProps) {
  const [searchResults, setSearchResults] = useState<TechniqueResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueResult | null>(null);

  // Debounce search input
  const debouncedValue = useDebounce(value, 300);

  // Search for techniques using vector similarity
  const searchTechniques = useCallback(async (query: string) => {
    if (!query.trim() || query.length < 2) {
      setSearchResults([]);
      setShowResults(false);
      return;
    }

    // If it looks like a valid technique/group ID, don't search
    const trimmedQuery = query.trim().toUpperCase();
    const isValidId = type === 'technique' 
      ? isValidTechniqueId(trimmedQuery) || /^T\d{1,4}(\.\d{1,3})?$/.test(trimmedQuery)
      : isValidGroupId(trimmedQuery) || /^G\d{1,4}$/.test(trimmedQuery);
      
    if (isValidId) {
      setSearchResults([]);
      setShowResults(false);
      return;
    }

    setIsLoading(true);
    try {
      const results = await apiClient.search.ttx({
        text: query,
        top_k: 5,
      });

      setSearchResults((results.results || []) as unknown as TechniqueResult[]);
      setShowResults(results.results?.length > 0);
    } catch (error) {
      console.error('Search error:', error);
      // For development: provide some mock results to demonstrate functionality
      if (process.env.NODE_ENV === 'development') {
        const mockResults = getMockSearchResults(query, type);
        setSearchResults(mockResults);
        setShowResults(mockResults.length > 0);
      } else {
        setSearchResults([]);
        setShowResults(false);
      }
    } finally {
      setIsLoading(false);
    }
  }, [type]);

  // Trigger search when debounced value changes
  useEffect(() => {
    if (debouncedValue !== value) return; // Only search on stable input
    searchTechniques(debouncedValue);
  }, [debouncedValue, searchTechniques]);

  // Handle technique selection
  const handleSelectTechnique = (technique: TechniqueResult) => {
    onChange(technique.external_id);
    setSelectedTechnique(technique);
    setShowResults(false);
  };

  // Clear selection when input changes manually
  useEffect(() => {
    if (selectedTechnique && value !== selectedTechnique.external_id) {
      setSelectedTechnique(null);
    }
  }, [value, selectedTechnique]);

  return (
    <div className={cn("relative", className)}>
      <div className="relative flex items-center gap-2">
        <div className="relative flex-1">
          <Input
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            disabled={disabled}
            className={cn(
              "pr-10",
              selectedTechnique && "border-green-500"
            )}
            onFocus={() => {
              if (searchResults.length > 0) {
                setShowResults(true);
              }
            }}
            onBlur={() => {
              // Delay hiding results to allow clicking
              setTimeout(() => setShowResults(false), 200);
            }}
          />
          
          <div className="absolute right-3 top-1/2 -translate-y-1/2">
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            ) : selectedTechnique ? (
              <CheckCircle className="h-4 w-4 text-green-500" />
            ) : (
              <Search className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </div>
        
        <InputExamples type={type} />
      </div>

      {/* Selected technique info */}
      {selectedTechnique && (
        <div className="mt-2">
          <Badge variant="secondary" className="text-xs">
            {selectedTechnique.name}
          </Badge>
        </div>
      )}

      {/* Search results dropdown */}
      {showResults && searchResults.length > 0 && (
        <Card className="absolute top-full left-0 right-0 z-50 mt-1 max-h-64 overflow-y-auto bg-background border shadow-lg">
          <CardContent className="p-2">
            <div className="space-y-1">
              {searchResults.map((result, index) => (
                <Button
                  key={result.stix_id}
                  variant="ghost"
                  className="w-full justify-start text-left h-auto p-2"
                  onClick={() => handleSelectTechnique(result)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className="text-xs">
                        {result.external_id}
                      </Badge>
                      <span className="font-medium truncate">
                        {result.name}
                      </span>
                      <div className="ml-auto flex items-center gap-1">
                        <Badge variant="secondary" className="text-xs">
                          {Math.round(result.score * 100)}%
                        </Badge>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground truncate">
                      {result.description}
                    </p>
                  </div>
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Search hint */}
      {!selectedTechnique && !isLoading && value.length > 0 && searchResults.length === 0 && (
        <p className="text-xs text-muted-foreground mt-1">
          {(() => {
            const trimmed = value.trim().toUpperCase();
            if (type === 'technique' && isValidTechniqueId(trimmed)) {
              return `✓ Valid technique ID: ${trimmed}`;
            } else if (type === 'group' && isValidGroupId(trimmed)) {
              return `✓ Valid group ID: ${trimmed}`;
            } else if (/^[TG]\d/.test(trimmed)) {
              return `Partial ${type} ID - continue typing or search by description`;
            } else {
              return `Search by description (e.g., "process injection") or enter ${type} ID`;
            }
          })()}
        </p>
      )}
    </div>
  );
}