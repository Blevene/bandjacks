"""Health check endpoints for monitoring and orchestration."""

import os
import time
import psutil
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from neo4j import GraphDatabase
from opensearchpy import OpenSearch
import redis
import logging

from bandjacks.services.api.settings import settings
from bandjacks.services.technique_cache import technique_cache
from bandjacks.services.actor_cache import actor_cache

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


def check_neo4j() -> Dict[str, Any]:
    """Check Neo4j connectivity and performance."""
    try:
        start = time.time()
        with GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        ) as driver:
            with driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) LIMIT 1")
                result.single()
        latency_ms = int((time.time() - start) * 1000)
        return {"status": "healthy", "latency_ms": latency_ms}
    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


def check_opensearch() -> Dict[str, Any]:
    """Check OpenSearch connectivity and indices."""
    try:
        start = time.time()
        client = OpenSearch(
            hosts=[settings.opensearch_url],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False
        )

        # Check cluster health
        health = client.cluster.health()

        # Check if main indices exist
        indices_exist = (
            client.indices.exists(index="attack_nodes") and
            client.indices.exists(index="bandjacks_reports")
        )

        latency_ms = int((time.time() - start) * 1000)

        if health["status"] in ["green", "yellow"] and indices_exist:
            return {
                "status": "healthy",
                "latency_ms": latency_ms,
                "cluster_status": health["status"],
                "indices": {"attack_nodes": True, "bandjacks_reports": True}
            }
        else:
            return {
                "status": "degraded",
                "latency_ms": latency_ms,
                "cluster_status": health["status"],
                "indices": {"attack_nodes": indices_exist}
            }
    except Exception as e:
        logger.error(f"OpenSearch health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity."""
    try:
        start = time.time()
        r = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password or None,
            decode_responses=True
        )
        r.ping()

        # Get some basic stats
        info = r.info()
        used_memory_mb = info.get("used_memory", 0) / (1024 * 1024)

        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "healthy",
            "latency_ms": latency_ms,
            "memory_mb": round(used_memory_mb, 2)
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


def check_caches() -> Dict[str, Any]:
    """Check if technique and actor caches are loaded."""
    # Access internal cache attributes
    try:
        technique_count = len(technique_cache._cache) if hasattr(technique_cache, '_cache') else 0
    except:
        technique_count = 0

    try:
        actor_count = len(actor_cache._cache) if hasattr(actor_cache, '_cache') else 0
    except:
        actor_count = 0

    if technique_count > 0:
        return {
            "status": "healthy",
            "technique_cache": {
                "count": technique_count,
                "loaded": True
            },
            "actor_cache": {
                "count": actor_count,
                "loaded": actor_count > 0
            }
        }
    else:
        return {
            "status": "degraded",
            "technique_cache": {
                "count": 0,
                "loaded": False
            },
            "actor_cache": {
                "count": actor_count,
                "loaded": actor_count > 0
            }
        }


def check_system_resources() -> Dict[str, Any]:
    """Check system resources (disk, memory, CPU)."""
    try:
        # Memory check
        memory = psutil.virtual_memory()
        memory_available_gb = memory.available / (1024**3)
        memory_percent = memory.percent

        # Disk check
        disk = psutil.disk_usage('/')
        disk_available_gb = disk.free / (1024**3)
        disk_percent = disk.percent

        # CPU check
        cpu_percent = psutil.cpu_percent(interval=0.1)

        status = "healthy"
        if memory_percent > 90 or disk_percent > 90:
            status = "degraded"
        if memory_percent > 95 or disk_percent > 95:
            status = "unhealthy"

        return {
            "status": status,
            "memory": {
                "available_gb": round(memory_available_gb, 2),
                "percent_used": round(memory_percent, 1)
            },
            "disk": {
                "available_gb": round(disk_available_gb, 2),
                "percent_used": round(disk_percent, 1)
            },
            "cpu": {
                "percent_used": round(cpu_percent, 1)
            }
        }
    except Exception as e:
        logger.error(f"System resource check failed: {e}")
        return {"status": "unknown", "error": str(e)}


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Basic health check endpoint.

    Returns 200 if the API is running, regardless of dependency status.
    Used for basic liveness checks.
    """
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0"
    }


@router.get("/health/live")
async def liveness_probe() -> Dict[str, Any]:
    """
    Kubernetes liveness probe endpoint.

    Returns 200 if the API process is alive and responding.
    Does not check external dependencies.
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/health/ready")
async def readiness_probe() -> Dict[str, Any]:
    """
    Kubernetes readiness probe endpoint with full dependency checks.

    Checks all external dependencies and returns appropriate status.
    Returns 503 if critical dependencies are unhealthy.
    """
    components = {}

    # Check each component
    components["neo4j"] = check_neo4j()
    components["opensearch"] = check_opensearch()
    components["redis"] = check_redis()
    components["caches"] = check_caches()
    components["system"] = check_system_resources()

    # Determine overall status
    critical_healthy = (
        components["neo4j"]["status"] == "healthy" and
        components["opensearch"]["status"] in ["healthy", "degraded"]
    )

    all_healthy = all(
        comp.get("status") in ["healthy", "degraded"]
        for comp in components.values()
    )

    if critical_healthy and all_healthy:
        overall_status = "healthy"
    elif critical_healthy:
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    response = {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "components": components
    }

    # Return 503 if unhealthy (for k8s probes)
    if overall_status == "unhealthy":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=response
        )

    return response


@router.get("/health/components/{component}")
async def component_health(component: str) -> Dict[str, Any]:
    """
    Check health of a specific component.

    Args:
        component: One of neo4j, opensearch, redis, caches, system

    Returns:
        Component health status
    """
    component_checks = {
        "neo4j": check_neo4j,
        "opensearch": check_opensearch,
        "redis": check_redis,
        "caches": check_caches,
        "system": check_system_resources
    }

    if component not in component_checks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown component: {component}"
        )

    result = component_checks[component]()
    return {
        "component": component,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **result
    }