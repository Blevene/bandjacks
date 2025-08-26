"use client";

import { HelpCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

interface InputExamplesProps {
  type: 'technique' | 'group';
}

const TECHNIQUE_EXAMPLES = [
  { id: 'T1055', name: 'Process Injection', description: 'Executing arbitrary code in address space of a separate process' },
  { id: 'T1003', name: 'OS Credential Dumping', description: 'Obtaining account login and password information' },
  { id: 'T1078', name: 'Valid Accounts', description: 'Using legitimate accounts to maintain access' },
  { id: 'T1053', name: 'Scheduled Task/Job', description: 'Scheduling tasks/jobs for execution at specified times' },
  { id: 'T1027', name: 'Obfuscated Files or Information', description: 'Making files/information difficult to discover' },
];

const GROUP_EXAMPLES = [
  { id: 'G0001', name: 'Axiom', description: 'Chinese cyber espionage group active since at least 2009' },
  { id: 'G0007', name: 'APT1', description: 'Chinese cyber espionage group active since at least 2006' },
  { id: 'G0016', name: 'APT29', description: 'Russian cyber espionage group active since at least 2008' },
  { id: 'G0028', name: 'Lazarus Group', description: 'North Korean state-sponsored cyber threat group' },
  { id: 'G0046', name: 'FIN7', description: 'Financial threat group active since at least 2015' },
];

const SEARCH_EXAMPLES = {
  technique: [
    'process injection',
    'credential dumping',
    'lateral movement',
    'persistence mechanisms',
    'privilege escalation',
    'defense evasion',
  ],
  group: [
    'Lazarus Group',
    'APT1',
    'Chinese espionage',
    'North Korean hackers',
    'Russian threat actors',
    'financial cybercriminals',
  ],
};

export function InputExamples({ type }: InputExamplesProps) {
  const examples = type === 'technique' ? TECHNIQUE_EXAMPLES : GROUP_EXAMPLES;
  const searchTerms = SEARCH_EXAMPLES[type];

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
          <HelpCircle className="h-4 w-4 text-muted-foreground" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-96" side="right">
        <Card className="border-0 shadow-none">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">
              {type === 'technique' ? 'ATT&CK Techniques' : 'Threat Groups'} 
            </CardTitle>
            <CardDescription className="text-xs">
              Enter IDs directly or use natural language search
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="text-xs font-medium mb-2">Common {type === 'technique' ? 'Technique' : 'Group'} IDs:</h4>
              <div className="space-y-2">
                {examples.slice(0, 3).map((example) => (
                  <div key={example.id} className="flex items-start gap-2">
                    <Badge variant="outline" className="text-xs">
                      {example.id}
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium">{example.name}</p>
                      <p className="text-xs text-muted-foreground truncate">
                        {example.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            <div>
              <h4 className="text-xs font-medium mb-2">Natural Language Search:</h4>
              <div className="flex flex-wrap gap-1">
                {searchTerms.slice(0, 4).map((term) => (
                  <Badge key={term} variant="secondary" className="text-xs">
                    "{term}"
                  </Badge>
                ))}
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Type descriptions to find {type === 'technique' ? 'techniques' : 'groups'} using AI-powered search
              </p>
            </div>

            <div className="border-t pt-3">
              <p className="text-xs text-muted-foreground">
                <strong>Pro tip:</strong> The system will automatically suggest relevant {type}s as you type
              </p>
            </div>
          </CardContent>
        </Card>
      </PopoverContent>
    </Popover>
  );
}