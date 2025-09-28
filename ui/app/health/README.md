# Health Status Page

A comprehensive system health monitoring dashboard for the Bandjacks platform.

## Features

### Real-time Health Monitoring
- **Overall System Status**: At-a-glance view of system health (healthy/degraded/unhealthy)
- **Component Health Checks**: Individual status for all critical components
- **Auto-refresh**: Updates every 10 seconds (configurable)
- **Manual Refresh**: On-demand status updates

### Monitored Components

#### 1. **Neo4j Database**
- Connection status
- Query latency measurements
- Error reporting

#### 2. **OpenSearch**
- Cluster health status (green/yellow/red)
- Index verification (attack_nodes, bandjacks_reports)
- Query latency

#### 3. **Redis Cache**
- Connection status
- Memory usage statistics
- Response latency

#### 4. **Application Caches**
- Technique cache status and count
- Actor cache status and count
- Loading verification

#### 5. **System Resources**
- **Memory**: Available RAM and usage percentage
- **Disk**: Available storage and usage percentage
- **CPU**: Current utilization percentage
- Visual progress bars with color-coded thresholds

### Visual Indicators

#### Status Badges
- 🟢 **Healthy**: Component fully operational
- 🟡 **Degraded**: Partially functional
- 🔴 **Unhealthy**: Component failed or unreachable
- ⚪ **Unknown**: Status cannot be determined

#### Progress Bar Colors
- **Green**: < 60% usage
- **Yellow**: 60-80% usage
- **Red**: > 80% usage

## Usage

Navigate to `/health` in the UI or click "Health Status" in the navigation menu.

### API Endpoints Used

The page fetches data from:
- `GET /health/ready` - Full system health check with all components

### Response Format

```json
{
  "status": "healthy",
  "timestamp": "2025-01-28T17:43:30.184036Z",
  "version": "1.0.0",
  "components": {
    "neo4j": { "status": "healthy", "latency_ms": 5 },
    "opensearch": {
      "status": "degraded",
      "cluster_status": "yellow",
      "indices": { "attack_nodes": false }
    },
    "redis": { "status": "healthy", "memory_mb": 1.69 },
    "caches": {
      "technique_cache": { "count": 993, "loaded": true },
      "actor_cache": { "count": 145, "loaded": true }
    },
    "system": {
      "memory": { "available_gb": 8.84, "percent_used": 72.4 },
      "disk": { "available_gb": 353.11, "percent_used": 2.9 },
      "cpu": { "percent_used": 7.7 }
    }
  }
}
```

## Development

### Component Location
- **Page Component**: `/app/health/page.tsx`
- **Navigation Link**: `/components/navigation.tsx`

### Technologies Used
- Next.js 14 App Router
- React Hooks (useState, useEffect)
- Tailwind CSS for styling
- Shadcn/ui components (Card, Badge, Button, Alert)
- Lucide React icons

### Error Handling
- Gracefully handles API failures
- Displays error alerts with descriptive messages
- Continues to function with cached data when possible

## Future Enhancements

Potential improvements:
- Historical health metrics graphs
- Alert thresholds configuration
- Email/Slack notifications for critical failures
- Detailed component diagnostics on click
- Export health reports
- Custom refresh intervals per component