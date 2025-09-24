'use client'

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

type Bundle = {
  techniques: string[];
  technique_names: string[];
  size: number;
  support: number;
  confidence: number;
  lift: number;
  tactics: string[];
  detection_coverage?: number;
  gap_count?: number;
};

export default function BundlesExplorerPage() {
  const [actor, setActor] = useState<string>('');
  const [minSupport, setMinSupport] = useState<number>(3);
  const [minSize, setMinSize] = useState<number>(3);
  const [maxSize, setMaxSize] = useState<number>(5);
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [stats, setStats] = useState<{ total_bundles?: number; coverage_stats?: any } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.cooccurrence.postBundles({
        intrusion_set_id: actor || undefined,
        min_support: minSupport,
        min_size: minSize,
        max_size: maxSize,
      });
      setBundles(res.data?.bundles ?? []);
      setStats({ total_bundles: res.data?.total_bundles, coverage_stats: res.data?.coverage_stats });
    } catch (e: any) {
      setError(e?.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Bundles Explorer</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Frequent technique bundles with confidence, lift, and D3FEND coverage</p>
          {stats && (
            <p className="text-xs text-gray-400 mt-1">bundles: {stats.total_bundles ?? '—'} · overall coverage: {stats.coverage_stats?.coverage_percentage ?? '—'}%</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="Intrusion Set STIX ID (optional)" className="h-9 rounded-md border px-3 text-sm bg-transparent w-80" />
          <label className="text-xs text-gray-500">min_support</label>
          <input type="number" value={minSupport} onChange={(e) => setMinSupport(parseInt(e.target.value || '3', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">min_size</label>
          <input type="number" value={minSize} onChange={(e) => setMinSize(parseInt(e.target.value || '3', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <label className="text-xs text-gray-500">max_size</label>
          <input type="number" value={maxSize} onChange={(e) => setMaxSize(parseInt(e.target.value || '5', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Apply</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Techniques</th>
              <th className="px-3 py-2 text-right">Size</th>
              <th className="px-3 py-2 text-right">Support</th>
              <th className="px-3 py-2 text-right">Confidence</th>
              <th className="px-3 py-2 text-right">Lift</th>
              <th className="px-3 py-2 text-left">Tactics</th>
              <th className="px-3 py-2 text-right">D3FEND Coverage</th>
              <th className="px-3 py-2 text-right">Gaps</th>
            </tr>
          </thead>
          <tbody>
            {bundles.map((b, idx) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-2">
                    {b.technique_names.map((name, i) => (
                      <span key={i} className="rounded-md border px-2 py-0.5 text-xs">{name}</span>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2 text-right">{b.size}</td>
                <td className="px-3 py-2 text-right">{b.support}</td>
                <td className="px-3 py-2 text-right">{Number(b.confidence).toFixed(3)}</td>
                <td className="px-3 py-2 text-right">{Number(b.lift).toFixed(2)}</td>
                <td className="px-3 py-2">{b.tactics.join(', ')}</td>
                <td className="px-3 py-2 text-right">{b.detection_coverage ?? 0}%</td>
                <td className="px-3 py-2 text-right">{b.gap_count ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


