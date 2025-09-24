'use client'

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function ConditionalCooccurrencePage() {
  const [techId, setTechId] = useState('T1007');
  const [limit, setLimit] = useState(25);
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!techId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.cooccurrence.getConditional(techId, limit);
      setRows(res.data?.results ?? []);
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
          <h1 className="text-xl font-semibold">Conditional Co-occurrence</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">P(B|A) for techniques co-occurring with a given technique</p>
        </div>
        <div className="flex items-center gap-2">
          <input value={techId} onChange={(e) => setTechId(e.target.value)} placeholder="Technique ID (e.g., T1007)" className="h-9 rounded-md border px-3 text-sm bg-transparent" />
          <input type="number" value={limit} onChange={(e) => setLimit(parseInt(e.target.value || '25', 10))} className="h-9 w-24 rounded-md border px-3 text-sm bg-transparent" />
          <button onClick={load} className="h-9 rounded-md bg-black text-white dark:bg-white dark:text-black px-3 text-sm">Run</button>
        </div>
      </div>

      {error && <div className="text-sm text-red-600">{error}</div>}
      {loading && <div className="text-sm text-gray-500">Loading…</div>}

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Co-technique</th>
              <th className="px-3 py-2 text-right">Episodes with A</th>
              <th className="px-3 py-2 text-right">Co-occurrence</th>
              <th className="px-3 py-2 text-right">P(B|A)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">{r.co_technique_name} <span className="text-xs text-gray-500">({r.co_technique})</span></td>
                <td className="px-3 py-2 text-right">{r.episodes_with_given}</td>
                <td className="px-3 py-2 text-right">{r.co_occurrence_count}</td>
                <td className="px-3 py-2 text-right">{Number(r.probability).toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


