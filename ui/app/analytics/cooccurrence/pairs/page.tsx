import { api } from '@/lib/api';

export default async function CooccurrencePairsPage() {
  const res = await api.cooccurrence.postGlobal({ min_support: 2, min_episodes_per_pair: 2, limit: 50 });
  const data = res.data as any;
  const pairs = (data?.pairs ?? []) as Array<any>;

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold">Pairs Explorer</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Top global co-occurring technique pairs</p>
        </div>
        {/* TODO: add filters (tactic/min support/episodes/sort) */}
      </div>

      <div className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-900/50">
            <tr>
              <th className="px-3 py-2 text-left">Technique A</th>
              <th className="px-3 py-2 text-left">Technique B</th>
              <th className="px-3 py-2 text-right">Count</th>
              <th className="px-3 py-2 text-right">Lift</th>
              <th className="px-3 py-2 text-right">PMI</th>
              <th className="px-3 py-2 text-right">NPMI</th>
              <th className="px-3 py-2 text-right">Jaccard</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((p: any, idx: number) => (
              <tr key={idx} className="border-t">
                <td className="px-3 py-2">{p.name_a} <span className="text-xs text-gray-500">({p.technique_a})</span></td>
                <td className="px-3 py-2">{p.name_b} <span className="text-xs text-gray-500">({p.technique_b})</span></td>
                <td className="px-3 py-2 text-right">{p.count}</td>
                <td className="px-3 py-2 text-right">{p.lift?.toFixed?.(2)}</td>
                <td className="px-3 py-2 text-right">{p.pmi?.toFixed?.(3)}</td>
                <td className="px-3 py-2 text-right">{p.npmi?.toFixed?.(3)}</td>
                <td className="px-3 py-2 text-right">{p.jaccard?.toFixed?.(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


