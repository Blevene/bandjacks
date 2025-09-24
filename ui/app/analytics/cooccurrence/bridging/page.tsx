'use client'

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

type BridgingRow = {
  technique_id: string;
  technique_name: string;
  actor_count: number;
  avg_importance: number;
  tactics: string[];
  actors_sample: Array<{ id: string; name: string }>;
};

export default function BridgingTechniquesPage() {
  const [minActors, setMinActors] = useState<number>(3);
  const [rows, setRows] = useState<BridgingRow[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.cooccurrence.getBridging(minActors);
      setRows(res.data?.techniques ?? []);
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
          <h1 className="text-xl font-semibold">Bridging Techniques</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Techniques used by many actors (prioritize for broad coverage)</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">min_actors</label>
          <input type="number" value={minActors} onChange={(e) => setMinActors(parseInt(e.target.value || '3', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Apply</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Technique</th>
              <th className="px-3 py-2 text-right">Actor Count</th>
              <th className="px-3 py-2 text-right">Avg Importance</th>
              <th className="px-3 py-2 text-left">Tactics</th>
              <th className="px-3 py-2 text-left">Actors (sample)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">
                  <div className="text-sm font-medium">{r.technique_name}</div>
                  <div className="text-[11px] text-gray-500">{r.technique_id}</div>
                </td>
                <td className="px-3 py-2 text-right">{r.actor_count}</td>
                <td className="px-3 py-2 text-right">{Number(r.avg_importance).toFixed(2)}</td>
                <td className="px-3 py-2">{r.tactics.join(', ')}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-2">
                    {r.actors_sample.map((a, i) => (
                      <span key={i} className="rounded-md border px-2 py-0.5 text-xs">{a.name}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


