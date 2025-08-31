# Bandjacks Frontend Architecture

## Table of Contents
1. [Overview](#overview)
2. [Next.js Application Structure](#nextjs-application-structure)
3. [Component Architecture](#component-architecture)
4. [State Management](#state-management)
5. [API Integration](#api-integration)
6. [UI Design System](#ui-design-system)
7. [Routing & Navigation](#routing--navigation)
8. [Performance Optimization](#performance-optimization)
9. [Testing Strategy](#testing-strategy)
10. [Build & Deployment](#build--deployment)

## Overview

The Bandjacks frontend is built with **Next.js 15.5.0** and **React 19.1.0**, providing a modern, type-safe interface for cyber threat intelligence analysis. The architecture emphasizes **performance**, **accessibility**, and **developer experience**.

### **Key Design Principles**
- **Component-Driven**: Reusable, composable UI components
- **Type Safety**: Full TypeScript coverage with generated API types
- **Performance First**: Optimized for fast loading and smooth interactions
- **Accessibility**: WCAG 2.1 compliant with screen reader support
- **Mobile Responsive**: Adaptive layouts for all screen sizes

### **Technology Stack**
- **Framework**: Next.js 15.5.0 with App Router
- **Language**: TypeScript 5.x with strict configuration
- **UI Library**: React 19.1.0 with concurrent features
- **Styling**: Tailwind CSS 4.x with custom design system
- **Components**: Radix UI for accessible primitives
- **State Management**: TanStack Query for server state
- **Testing**: Jest + React Testing Library + MSW

## Next.js Application Structure

### **App Router Structure**
```
ui/
├── app/                        # App Router (Next.js 13+)
│   ├── layout.tsx             # Root layout with providers
│   ├── page.tsx               # Dashboard/home page
│   ├── globals.css            # Global styles
│   ├── reports/               # Report management
│   │   ├── page.tsx           # Reports list
│   │   ├── new/               # Report creation
│   │   │   └── page.tsx       # Upload/create form
│   │   └── [id]/              # Dynamic report routes
│   │       ├── page.tsx       # Report detail view
│   │       ├── review/        # Review interface
│   │       │   └── page.tsx   # Unified review page
│   │       └── flows/         # Attack flow visualization
│   │           └── page.tsx   # Flow diagram
│   ├── analytics/             # Analytics dashboard
│   │   └── page.tsx           # Coverage analytics
│   └── admin/                 # Administrative pages
│       └── page.tsx           # System administration
├── components/                # Reusable components
│   ├── ui/                   # Design system components
│   ├── reports/              # Report-specific components
│   ├── navigation/           # Navigation components
│   └── charts/               # Data visualization
├── lib/                      # Utility libraries
│   ├── api.ts               # API client configuration
│   ├── utils.ts             # Common utilities
│   └── report-types.ts      # TypeScript definitions
├── hooks/                    # Custom React hooks
│   ├── use-api.ts           # API interaction hooks
│   └── use-reports.ts       # Report-specific hooks
└── public/                   # Static assets
    ├── icons/               # Icon assets
    └── images/              # Image assets
```

### **Root Layout (`app/layout.tsx`)**

```typescript
import { ThemeProvider } from "@/components/theme-provider"
import { Navigation } from "@/components/navigation"
import { Toaster } from "@/components/ui/toaster"

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          <div className="flex h-screen overflow-hidden">
            <Navigation />
            <main className="flex-1 overflow-y-auto bg-background">
              <div className="container mx-auto p-6">
                {children}
              </div>
            </main>
          </div>
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  )
}
```

### **Configuration Files**

#### **Next.js Config (`next.config.ts`)**
```typescript
/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    typedRoutes: true,        // Type-safe routing
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:8000/v1/:path*'
      }
    ]
  }
}

export default nextConfig
```

#### **TypeScript Config (`tsconfig.json`)**
```json
{
  "compilerOptions": {
    "target": "ES2017",
    "lib": ["dom", "dom.iterable", "ES2017"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./*"]
    }
  }
}
```

## Component Architecture

### **Component Hierarchy**

```
App
├── ThemeProvider (Context)
├── QueryClient (TanStack Query)
├── Navigation
│   ├── NavLinks
│   ├── UserProfile
│   └── ThemeToggle
└── Page Components
    ├── ReportList
    │   ├── ReportCard
    │   ├── StatusBadge
    │   └── ActionMenu
    ├── ReportUpload
    │   ├── DropZone
    │   ├── ProgressBar
    │   └── JobStatus
    └── UnifiedReview
        ├── ReviewTabs
        ├── ReviewFilters
        ├── ReviewProgress
        └── ReviewItemCard
            ├── ItemHeader
            ├── EvidenceSection
            └── ActionButtons
```

### **Design System Components (`components/ui/`)**

The UI components are built on **Radix UI** primitives with custom styling:

#### **Button Component**
```typescript
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        outline: "border border-input bg-background hover:bg-accent hover:text-accent-foreground",
        secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 rounded-md px-3",
        lg: "h-11 rounded-md px-8",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
```

#### **Dialog Component**
```typescript
import * as DialogPrimitive from "@radix-ui/react-dialog"

const Dialog = DialogPrimitive.Root
const DialogTrigger = DialogPrimitive.Trigger
const DialogPortal = DialogPrimitive.Portal
const DialogClose = DialogPrimitive.Close

const DialogOverlay = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Overlay>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Overlay>
>(({ className, ...props }, ref) => (
  <DialogPrimitive.Overlay
    ref={ref}
    className={cn(
      "fixed inset-0 z-50 bg-black/80 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
      className
    )}
    {...props}
  />
))

const DialogContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPortal>
    <DialogOverlay />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border bg-background p-6 shadow-lg duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%] sm:rounded-lg",
        className
      )}
      {...props}
    >
      {children}
      <DialogPrimitive.Close className="absolute right-4 top-4 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none data-[state=open]:bg-accent data-[state=open]:text-muted-foreground">
        <X className="h-4 w-4" />
        <span className="sr-only">Close</span>
      </DialogPrimitive.Close>
    </DialogPrimitive.Content>
  </DialogPortal>
))
```

### **Feature Components (`components/reports/`)**

#### **Unified Review Component**
```typescript
import { useState, useMemo } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ReviewItemCard } from './review-item-card'
import { ReviewProgress } from './review-progress'
import { ReviewFilters } from './review-filters'

interface UnifiedReviewProps {
  report: Report
  onSubmit: (decisions: UnifiedReviewDecision[], globalNotes: string) => Promise<void>
  readOnly?: boolean
}

export function UnifiedReview({ report, onSubmit, readOnly = false }: UnifiedReviewProps) {
  const [reviewState, setReviewState] = useState(() => 
    createUnifiedReviewState(report)
  )
  const [activeTab, setActiveTab] = useState('all')
  
  // Filter items based on current tab and filters
  const filteredItems = useMemo(() => {
    return filterReviewableItems(reviewState.items, {
      ...reviewState,
      filterType: activeTab === 'all' ? undefined : activeTab as any
    })
  }, [reviewState, activeTab])
  
  // Calculate progress statistics
  const progress = useMemo(() => 
    calculateReviewProgress(reviewState.items), 
    [reviewState.items]
  )
  
  const handleReviewAction = (itemId: string, action: ReviewAction) => {
    const decision: UnifiedReviewDecision = {
      item_id: itemId,
      action: action.type,
      edited_value: action.type === 'edit' ? action.editedValue : undefined,
      confidence_adjustment: action.confidenceAdjustment,
      notes: action.notes,
      timestamp: new Date().toISOString()
    }
    
    setReviewState(prev => ({
      ...prev,
      decisions: new Map(prev.decisions.set(itemId, decision))
    }))
  }
  
  const handleSubmitReview = async () => {
    const decisions = Array.from(reviewState.decisions.values())
    await onSubmit(decisions, reviewState.globalNotes)
  }
  
  return (
    <div className="flex h-full gap-6">
      {/* Main Review Area */}
      <div className="flex-1 flex flex-col">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold">Review Report: {report.name}</h1>
          <Button 
            onClick={handleSubmitReview}
            disabled={reviewState.decisions.size === 0 || readOnly}
          >
            Submit Review ({reviewState.decisions.size} decisions)
          </Button>
        </div>
        
        <ReviewFilters 
          state={reviewState}
          onStateChange={setReviewState}
        />
        
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="all">All Items ({reviewState.items.length})</TabsTrigger>
            <TabsTrigger value="entity">Entities ({progress.byType.entities})</TabsTrigger>
            <TabsTrigger value="technique">Techniques ({progress.byType.techniques})</TabsTrigger>
            <TabsTrigger value="flow_step">Flow Steps ({progress.byType.flowSteps})</TabsTrigger>
            <TabsTrigger value="summary">Summary</TabsTrigger>
          </TabsList>
          
          <TabsContent value={activeTab} className="flex-1 overflow-hidden">
            {activeTab === 'summary' ? (
              <ReviewSummary 
                progress={progress}
                globalNotes={reviewState.globalNotes}
                onGlobalNotesChange={(notes) => 
                  setReviewState(prev => ({ ...prev, globalNotes: notes }))
                }
              />
            ) : (
              <div className="grid gap-4 overflow-y-auto">
                {filteredItems.map(item => (
                  <ReviewItemCard
                    key={item.id}
                    item={item}
                    decision={reviewState.decisions.get(item.id)}
                    onReviewAction={(action) => handleReviewAction(item.id, action)}
                    readOnly={readOnly}
                  />
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
      
      {/* Progress Sidebar */}
      <div className="w-80">
        <ReviewProgress progress={progress} />
      </div>
    </div>
  )
}
```

#### **Review Item Card Component**
```typescript
interface ReviewItemCardProps {
  item: ReviewableItem
  decision?: UnifiedReviewDecision
  onReviewAction: (action: ReviewAction) => void
  readOnly?: boolean
}

export function ReviewItemCard({ 
  item, 
  decision, 
  onReviewAction, 
  readOnly = false 
}: ReviewItemCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  
  const getStatusBadge = () => {
    if (!decision) return <Badge variant="secondary">Pending</Badge>
    
    switch (decision.action) {
      case 'approve':
        return <Badge variant="success">Approved</Badge>
      case 'reject':
        return <Badge variant="destructive">Rejected</Badge>
      case 'edit':
        return <Badge variant="warning">Edited</Badge>
      default:
        return <Badge variant="secondary">Pending</Badge>
    }
  }
  
  const getItemIcon = () => {
    switch (item.type) {
      case 'entity':
        return <Users className="h-4 w-4" />
      case 'technique':
        return <Target className="h-4 w-4" />
      case 'flow_step':
        return <ArrowRight className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }
  
  return (
    <Card className="transition-all hover:shadow-md">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3 flex-1">
            <div className="mt-1">
              {getItemIcon()}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-medium truncate">{item.name}</h3>
                <Badge variant="outline" className="text-xs">
                  {item.type.replace('_', ' ')}
                </Badge>
                {item.category && (
                  <Badge variant="secondary" className="text-xs">
                    {item.category}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <span>Confidence: {item.confidence}%</span>
                {item.line_refs && item.line_refs.length > 0 && (
                  <span>Lines: {item.line_refs.join(', ')}</span>
                )}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {getStatusBadge()}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="pt-0">
          {/* Evidence Section */}
          {item.evidence && item.evidence.length > 0 && (
            <div className="mb-4">
              <h4 className="font-medium mb-2">Evidence</h4>
              <div className="bg-muted/50 rounded-md p-3 space-y-2">
                {item.evidence.map((evidence, index) => (
                  <p key={index} className="text-sm">
                    "{evidence}"
                  </p>
                ))}
              </div>
            </div>
          )}
          
          {/* Metadata Section */}
          {item.metadata && Object.keys(item.metadata).length > 0 && (
            <div className="mb-4">
              <h4 className="font-medium mb-2">Metadata</h4>
              <div className="text-sm space-y-1">
                {Object.entries(item.metadata).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-muted-foreground">{key}:</span>
                    <span>{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Decision Notes */}
          {decision?.notes && (
            <div className="mb-4">
              <h4 className="font-medium mb-2">Review Notes</h4>
              <p className="text-sm bg-muted/50 rounded-md p-3">
                {decision.notes}
              </p>
            </div>
          )}
        </CardContent>
      )}
      
      {!readOnly && (
        <CardFooter className="pt-3">
          <div className="flex gap-2 w-full">
            <Button 
              variant="success" 
              size="sm"
              onClick={() => onReviewAction({ type: 'approve' })}
              disabled={decision?.action === 'approve'}
            >
              <Check className="h-4 w-4 mr-1" />
              Approve
            </Button>
            <Button 
              variant="destructive" 
              size="sm"
              onClick={() => onReviewAction({ type: 'reject' })}
              disabled={decision?.action === 'reject'}
            >
              <X className="h-4 w-4 mr-1" />
              Reject
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setIsEditing(true)}
            >
              <Edit className="h-4 w-4 mr-1" />
              Edit
            </Button>
          </div>
        </CardFooter>
      )}
      
      {/* Edit Dialog */}
      <EditItemDialog
        item={item}
        isOpen={isEditing}
        onClose={() => setIsEditing(false)}
        onSave={(editedValue, notes, confidenceAdjustment) => {
          onReviewAction({
            type: 'edit',
            editedValue,
            notes,
            confidenceAdjustment
          })
          setIsEditing(false)
        }}
      />
    </Card>
  )
}
```

## State Management

### **TanStack Query for Server State**

```typescript
// hooks/use-reports.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'

export function useReports() {
  return useQuery({
    queryKey: ['reports'],
    queryFn: () => api.reports.getReports(),
    staleTime: 30_000, // 30 seconds
  })
}

export function useReport(id: string) {
  return useQuery({
    queryKey: ['reports', id],
    queryFn: () => api.reports.getReport(id),
    enabled: !!id,
  })
}

export function useUploadReport() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: api.reports.uploadReport,
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      queryClient.setQueryData(['reports', report.id], report)
    },
  })
}

export function useSubmitReview(reportId: string) {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: ReviewSubmission) => 
      api.reports.submitUnifiedReview(reportId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports', reportId] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    },
  })
}
```

### **Local State with Zustand (for complex UI state)**

```typescript
// stores/review-store.ts
import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

interface ReviewStore {
  // State
  reviewState: UnifiedReviewState | null
  selectedItems: Set<string>
  isSubmitting: boolean
  
  // Actions
  setReviewState: (state: UnifiedReviewState) => void
  updateDecision: (itemId: string, decision: UnifiedReviewDecision) => void
  toggleItemSelection: (itemId: string) => void
  clearSelection: () => void
  setSubmitting: (submitting: boolean) => void
  
  // Computed values
  getProgress: () => ReviewProgress
  getFilteredItems: () => ReviewableItem[]
}

export const useReviewStore = create<ReviewStore>()(
  devtools(
    (set, get) => ({
      // Initial state
      reviewState: null,
      selectedItems: new Set(),
      isSubmitting: false,
      
      // Actions
      setReviewState: (state) => set({ reviewState: state }),
      
      updateDecision: (itemId, decision) => set((state) => {
        if (!state.reviewState) return state
        
        const newDecisions = new Map(state.reviewState.decisions)
        newDecisions.set(itemId, decision)
        
        return {
          reviewState: {
            ...state.reviewState,
            decisions: newDecisions
          }
        }
      }),
      
      toggleItemSelection: (itemId) => set((state) => {
        const newSelection = new Set(state.selectedItems)
        if (newSelection.has(itemId)) {
          newSelection.delete(itemId)
        } else {
          newSelection.add(itemId)
        }
        return { selectedItems: newSelection }
      }),
      
      clearSelection: () => set({ selectedItems: new Set() }),
      setSubmitting: (submitting) => set({ isSubmitting: submitting }),
      
      // Computed values
      getProgress: () => {
        const state = get().reviewState
        return state ? calculateReviewProgress(state.items) : getEmptyProgress()
      },
      
      getFilteredItems: () => {
        const state = get().reviewState
        return state ? filterReviewableItems(state.items, state) : []
      }
    }),
    { name: 'review-store' }
  )
)
```

## API Integration

### **Type-Safe API Client**

```typescript
// lib/api.ts
import { OpenAPIClientAxios } from 'openapi-client-axios'
import type { Client } from './generated/api-types'

const api = new OpenAPIClientAxios({
  definition: '/api/openapi.json',
  withServer: 0
})

let client: Client

export async function getApiClient(): Promise<Client> {
  if (!client) {
    client = await api.init<Client>()
  }
  return client
}

// Typed API wrapper
export const typedApi = {
  reports: {
    async getReports() {
      const client = await getApiClient()
      const response = await client.getReports()
      return response.data
    },
    
    async getReport(id: string) {
      const client = await getApiClient()
      const response = await client.getReport({ id })
      return response.data
    },
    
    async uploadReport(file: File, config?: UploadConfig) {
      const client = await getApiClient()
      const formData = new FormData()
      formData.append('file', file)
      if (config) {
        formData.append('config', JSON.stringify(config))
      }
      
      const response = await client.uploadReport(null, {
        headers: { 'Content-Type': 'multipart/form-data' },
        data: formData
      })
      return response.data
    },
    
    async submitUnifiedReview(reportId: string, submission: ReviewSubmission) {
      const client = await getApiClient()
      const response = await client.submitUnifiedReview({ 
        reportId 
      }, submission)
      return response.data
    }
  },
  
  jobs: {
    async getJobStatus(jobId: string) {
      const client = await getApiClient()
      const response = await client.getJobStatus({ jobId })
      return response.data
    }
  }
}
```

### **Real-time Job Status Polling**

```typescript
// hooks/use-job-status.ts
import { useQuery } from '@tanstack/react-query'
import { typedApi } from '@/lib/api'

interface UseJobStatusOptions {
  jobId: string
  enabled: boolean
  onComplete?: (result: any) => void
  onError?: (error: string) => void
}

export function useJobStatus({ 
  jobId, 
  enabled, 
  onComplete, 
  onError 
}: UseJobStatusOptions) {
  return useQuery({
    queryKey: ['job-status', jobId],
    queryFn: () => typedApi.jobs.getJobStatus(jobId),
    enabled: enabled && !!jobId,
    refetchInterval: (data) => {
      // Dynamic polling interval based on status
      if (!data?.data) return 2000
      
      const status = data.data.status
      if (status === 'completed' || status === 'failed') {
        // Stop polling
        if (status === 'completed' && onComplete) {
          onComplete(data.data.result)
        }
        if (status === 'failed' && onError) {
          onError(data.data.error || 'Job failed')
        }
        return false
      }
      
      // Adaptive polling: faster initially, slower as job progresses
      const progress = data.data.progress || 0
      if (progress < 25) return 2000  // 2s
      if (progress < 75) return 5000  // 5s
      return 10000 // 10s
    },
    refetchIntervalInBackground: true,
  })
}
```

## UI Design System

### **Theme Configuration (`tailwind.config.js`)**

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './app/**/*.{ts,tsx}',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: 0 },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: 0 },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
}
```

### **CSS Variables (`app/globals.css`)**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 84% 4.9%;
    --card: 0 0% 100%;
    --card-foreground: 222.2 84% 4.9%;
    --popover: 0 0% 100%;
    --popover-foreground: 222.2 84% 4.9%;
    --primary: 221.2 83.2% 53.3%;
    --primary-foreground: 210 40% 98%;
    --secondary: 210 40% 96%;
    --secondary-foreground: 222.2 84% 4.9%;
    --muted: 210 40% 96%;
    --muted-foreground: 215.4 16.3% 46.9%;
    --accent: 210 40% 96%;
    --accent-foreground: 222.2 84% 4.9%;
    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 210 40% 98%;
    --border: 214.3 31.8% 91.4%;
    --input: 214.3 31.8% 91.4%;
    --ring: 221.2 83.2% 53.3%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 222.2 84% 4.9%;
    --foreground: 210 40% 98%;
    --card: 222.2 84% 4.9%;
    --card-foreground: 210 40% 98%;
    --popover: 222.2 84% 4.9%;
    --popover-foreground: 210 40% 98%;
    --primary: 217.2 91.2% 59.8%;
    --primary-foreground: 222.2 84% 4.9%;
    --secondary: 217.2 32.6% 17.5%;
    --secondary-foreground: 210 40% 98%;
    --muted: 217.2 32.6% 17.5%;
    --muted-foreground: 215 20.2% 65.1%;
    --accent: 217.2 32.6% 17.5%;
    --accent-foreground: 210 40% 98%;
    --destructive: 0 62.8% 30.6%;
    --destructive-foreground: 210 40% 98%;
    --border: 217.2 32.6% 17.5%;
    --input: 217.2 32.6% 17.5%;
    --ring: 224.3 76.3% 94.1%;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground;
  }
}

@layer components {
  .container {
    @apply mx-auto max-w-7xl px-4 sm:px-6 lg:px-8;
  }
  
  .btn-primary {
    @apply bg-primary text-primary-foreground hover:bg-primary/90;
  }
  
  .btn-secondary {
    @apply bg-secondary text-secondary-foreground hover:bg-secondary/80;
  }
}
```

## Routing & Navigation

### **Navigation Component**

```typescript
// components/navigation.tsx
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Analytics', href: '/analytics', icon: BarChart },
  { name: 'Admin', href: '/admin', icon: Settings },
]

export function Navigation() {
  const pathname = usePathname()
  
  return (
    <nav className="w-64 bg-card border-r border-border">
      <div className="p-6">
        <h1 className="text-xl font-bold">Bandjacks</h1>
      </div>
      
      <div className="px-3">
        {navigation.map((item) => {
          const isActive = pathname === item.href || 
            (item.href !== '/' && pathname.startsWith(item.href))
          
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center px-3 py-2 mb-1 rounded-md text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent'
              )}
            >
              <item.icon className="mr-3 h-4 w-4" />
              {item.name}
            </Link>
          )
        })}
      </div>
    </nav>
  )
}
```

### **Dynamic Route Handling**

```typescript
// app/reports/[id]/page.tsx
interface PageProps {
  params: { id: string }
  searchParams: { tab?: string }
}

export default function ReportDetailPage({ params, searchParams }: PageProps) {
  const { data: report, isLoading, error } = useReport(params.id)
  const activeTab = searchParams.tab || 'overview'
  
  if (isLoading) return <ReportDetailSkeleton />
  if (error) return <ErrorPage error={error} />
  if (!report) return <NotFoundPage />
  
  return (
    <div className="space-y-6">
      <ReportHeader report={report} />
      
      <Tabs value={activeTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="entities">Entities</TabsTrigger>
          <TabsTrigger value="techniques">Techniques</TabsTrigger>
          <TabsTrigger value="flows">Attack Flows</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview">
          <ReportOverview report={report} />
        </TabsContent>
        
        <TabsContent value="entities">
          <EntityList entities={report.extraction?.entities} />
        </TabsContent>
        
        <TabsContent value="techniques">
          <TechniqueList claims={report.extraction?.claims} />
        </TabsContent>
        
        <TabsContent value="flows">
          <FlowVisualization flow={report.extraction?.flow} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
```

## Performance Optimization

### **Code Splitting & Lazy Loading**

```typescript
// Lazy load heavy components
const FlowVisualization = lazy(() => import('@/components/flow-visualization'))
const UnifiedReview = lazy(() => import('@/components/reports/unified-review'))

// Usage with Suspense
<Suspense fallback={<FlowVisualizationSkeleton />}>
  <FlowVisualization flow={report.flow} />
</Suspense>
```

### **Image Optimization**

```typescript
import Image from 'next/image'

// Optimized image loading
<Image
  src="/images/diagram.png"
  alt="Architecture diagram"
  width={800}
  height={600}
  priority={false}
  loading="lazy"
  placeholder="blur"
  blurDataURL="data:image/jpeg;base64,..."
/>
```

### **Bundle Analysis**

```javascript
// next.config.js
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

module.exports = withBundleAnalyzer({
  // ... other config
})
```

## Testing Strategy

### **Component Testing with RTL**

```typescript
// __tests__/components/review-item-card.test.tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { ReviewItemCard } from '@/components/reports/review-item-card'

const mockItem: ReviewableItem = {
  id: 'entity-malware-0',
  type: 'entity',
  category: 'malware',
  name: 'Test Malware',
  confidence: 85,
  evidence: ['Found malware sample'],
  line_refs: [10, 11]
}

describe('ReviewItemCard', () => {
  it('renders item information correctly', () => {
    render(
      <ReviewItemCard 
        item={mockItem} 
        onReviewAction={jest.fn()}
      />
    )
    
    expect(screen.getByText('Test Malware')).toBeInTheDocument()
    expect(screen.getByText('malware')).toBeInTheDocument()
    expect(screen.getByText('Confidence: 85%')).toBeInTheDocument()
  })
  
  it('calls onReviewAction when approve button clicked', () => {
    const mockOnReviewAction = jest.fn()
    render(
      <ReviewItemCard 
        item={mockItem} 
        onReviewAction={mockOnReviewAction}
      />
    )
    
    fireEvent.click(screen.getByText('Approve'))
    expect(mockOnReviewAction).toHaveBeenCalledWith({
      type: 'approve'
    })
  })
  
  it('expands evidence section when clicked', () => {
    render(
      <ReviewItemCard 
        item={mockItem} 
        onReviewAction={jest.fn()}
      />
    )
    
    // Evidence should not be visible initially
    expect(screen.queryByText('Found malware sample')).not.toBeInTheDocument()
    
    // Click expand button
    fireEvent.click(screen.getByRole('button', { name: /expand/i }))
    
    // Evidence should now be visible
    expect(screen.getByText('Found malware sample')).toBeInTheDocument()
  })
})
```

### **API Mocking with MSW**

```typescript
// mocks/handlers.ts
import { rest } from 'msw'

export const handlers = [
  rest.get('/api/reports', (req, res, ctx) => {
    return res(
      ctx.json([
        {
          id: 'report-1',
          name: 'Test Report',
          status: 'completed',
          created: '2025-08-31T10:00:00Z'
        }
      ])
    )
  }),
  
  rest.get('/api/reports/:id', (req, res, ctx) => {
    const { id } = req.params
    
    return res(
      ctx.json({
        id,
        name: 'Test Report',
        status: 'completed',
        extraction: {
          entities: {
            malware: [
              {
                name: 'Test Malware',
                confidence: 85,
                evidence: ['Found sample']
              }
            ]
          }
        }
      })
    )
  }),
  
  rest.post('/api/reports/:id/unified-review', (req, res, ctx) => {
    return res(
      ctx.json({
        success: true,
        items_reviewed: 5,
        items_approved: 3,
        items_rejected: 2
      })
    )
  })
]
```

### **Integration Tests**

```typescript
// __tests__/integration/review-workflow.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { server } from '@/mocks/server'
import { UnifiedReview } from '@/components/reports/unified-review'

describe('Review Workflow Integration', () => {
  let queryClient: QueryClient
  
  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false }
      }
    })
  })
  
  const renderWithProviders = (ui: React.ReactElement) => {
    return render(
      <QueryClientProvider client={queryClient}>
        {ui}
      </QueryClientProvider>
    )
  }
  
  it('completes full review workflow', async () => {
    const mockOnSubmit = jest.fn()
    const mockReport = {
      id: 'report-1',
      name: 'Test Report',
      extraction: {
        entities: {
          malware: [
            { name: 'Test Malware', confidence: 85, evidence: ['Sample found'] }
          ]
        }
      }
    }
    
    renderWithProviders(
      <UnifiedReview 
        report={mockReport} 
        onSubmit={mockOnSubmit}
      />
    )
    
    // Verify initial render
    expect(screen.getByText('Review Report: Test Report')).toBeInTheDocument()
    expect(screen.getByText('Test Malware')).toBeInTheDocument()
    
    // Approve the item
    fireEvent.click(screen.getByText('Approve'))
    
    // Submit review
    fireEvent.click(screen.getByText(/Submit Review/))
    
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            action: 'approve',
            item_id: 'entity-malware-0'
          })
        ]),
        ''
      )
    })
  })
})
```

## Build & Deployment

### **Build Configuration**

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "type-check": "tsc --noEmit",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:ci": "jest --ci --coverage --maxWorkers=2",
    "analyze": "ANALYZE=true next build"
  }
}
```

### **Production Optimization**

```javascript
// next.config.js (production)
const nextConfig = {
  output: 'standalone',
  
  // Optimize for production
  swcMinify: true,
  
  // Enable experimental features
  experimental: {
    optimizeCss: true,
    optimizePackageImports: ['@radix-ui/react-icons']
  },
  
  // Image optimization
  images: {
    formats: ['image/webp', 'image/avif'],
    minimumCacheTTL: 60,
  },
  
  // Headers for security and caching
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'origin-when-cross-origin'
          }
        ]
      }
    ]
  }
}
```

### **Docker Configuration**

```dockerfile
# Dockerfile
FROM node:18-alpine AS base
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Dependencies
FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Builder
FROM base AS builder
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Runner
FROM base AS runner
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT 3000

CMD ["node", "server.js"]
```

## Conclusion

The Bandjacks frontend architecture provides a **modern, performant, and maintainable** foundation for cyber threat intelligence analysis. Key architectural strengths:

- **Type Safety**: Full TypeScript coverage with generated API types
- **Performance**: Optimized loading, code splitting, and caching strategies  
- **Accessibility**: WCAG 2.1 compliant with Radix UI primitives
- **Developer Experience**: Hot reload, comprehensive testing, and clear patterns
- **Scalability**: Component-driven architecture with efficient state management

The system successfully delivers a **sophisticated user interface** while maintaining **code quality** and **development velocity**.