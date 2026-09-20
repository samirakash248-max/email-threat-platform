import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

analytics_component = """
export function AnalyticsView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch('/api/analytics/detection')
      .then(res => res.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="p-8 text-red-500 font-medium">
        Error loading analytics: {data?.error || 'Unknown error'}
      </div>
    );
  }

  const { overall, confusion_matrix: cm, rule_performance, category_performance, dataset_size } = data;

  return (
    <div className="flex flex-col h-full overflow-hidden bg-slate-50 relative">
      <div className="border-b border-slate-200 bg-white p-6 shadow-sm z-10 flex-shrink-0">
        <h1 className="text-2xl font-bold text-slate-900 mb-1 flex items-center gap-2">
          <Activity className="w-6 h-6 text-blue-600" />
          Detection Analytics & Evaluation
        </h1>
        <p className="text-sm text-slate-500">
          Transparent performance evaluation against a labeled dataset of {dataset_size} samples.
        </p>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          
          {/* Overall Performance & Confusion Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Overall Metrics</h2>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Accuracy</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.accuracy * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Precision</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.precision * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">Recall</div>
                  <div className="text-2xl font-bold text-slate-800">{(overall.recall * 100).toFixed(1)}%</div>
                </div>
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1">F1 Score</div>
                  <div className="text-2xl font-bold text-blue-600">{(overall.f1 * 100).toFixed(1)}%</div>
                </div>
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Confusion Matrix (Binary)</h2>
              <div className="grid grid-cols-3 gap-2 text-center text-sm mt-6">
                <div className="font-semibold text-slate-500 flex items-center justify-center">Actual \\ Pred</div>
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded">Benign</div>
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded">Malicious</div>
                
                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded flex items-center justify-center">Benign</div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-green-700">{cm.tn}</div>
                  <div className="text-xs text-green-600">True Negative</div>
                </div>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-red-700">{cm.fp}</div>
                  <div className="text-xs text-red-600">False Positive</div>
                </div>

                <div className="font-semibold text-slate-700 bg-slate-100 p-2 rounded flex items-center justify-center">Malicious</div>
                <div className="bg-red-50 border border-red-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-red-700">{cm.fn}</div>
                  <div className="text-xs text-red-600">False Negative</div>
                </div>
                <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                  <div className="text-2xl font-bold text-green-700">{cm.tp}</div>
                  <div className="text-xs text-green-600">True Positive</div>
                </div>
              </div>
            </div>
          </div>

          {/* Category Performance */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Threat Category Performance</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-500 uppercase bg-slate-50">
                  <tr>
                    <th className="px-4 py-3 font-semibold rounded-tl-lg">Category</th>
                    <th className="px-4 py-3 font-semibold">Samples</th>
                    <th className="px-4 py-3 font-semibold">Detected</th>
                    <th className="px-4 py-3 font-semibold">Missed (FN)</th>
                    <th className="px-4 py-3 font-semibold">Precision</th>
                    <th className="px-4 py-3 font-semibold">Recall</th>
                    <th className="px-4 py-3 font-semibold rounded-tr-lg">F1 Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Object.entries(category_performance).map(([cat, stats]) => (
                    <tr key={cat} className="hover:bg-slate-50/50">
                      <td className="px-4 py-3 font-medium text-slate-900">{cat}</td>
                      <td className="px-4 py-3 text-slate-600">{stats.samples}</td>
                      <td className="px-4 py-3 text-green-600 font-medium">{stats.detected}</td>
                      <td className="px-4 py-3 text-red-600 font-medium">{stats.fn}</td>
                      <td className="px-4 py-3">{(stats.precision * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3">{(stats.recall * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3 text-blue-600 font-semibold">{(stats.f1 * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Rule Analytics */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <h2 className="text-lg font-bold text-slate-800 mb-4 border-b border-slate-100 pb-2">Rule Analytics (Triggered Rules)</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-500 uppercase bg-slate-50">
                  <tr>
                    <th className="px-4 py-3 font-semibold rounded-tl-lg">Rule ID</th>
                    <th className="px-4 py-3 font-semibold">Rule Name</th>
                    <th className="px-4 py-3 font-semibold">Hits</th>
                    <th className="px-4 py-3 font-semibold rounded-tr-lg">Avg Score Contribution</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {rule_performance.sort((a,b) => b.times_triggered - a.times_triggered).map((r) => (
                    <tr key={r.rule_id} className="hover:bg-slate-50/50">
                      <td className="px-4 py-3 font-medium text-slate-700 whitespace-nowrap">{r.rule_id}</td>
                      <td className="px-4 py-3 text-slate-900">{r.rule_name}</td>
                      <td className="px-4 py-3 text-slate-600 font-semibold">{r.times_triggered}</td>
                      <td className="px-4 py-3 text-orange-600 font-semibold">+{r.avg_score_contribution.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Info block */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mt-8">
            <h3 className="font-semibold text-blue-800 mb-2 flex items-center gap-2">
              <HelpCircle className="w-4 h-4"/> Methodology Notes
            </h3>
            <ul className="text-sm text-blue-900 space-y-1 ml-6 list-disc">
              <li>Metrics are calculated dynamically against the local `samples/labels.json` dataset.</li>
              <li>A sample is classified as "Malicious" if the scanner's overall threat score exceeds 40.</li>
              <li>Due to the small size of this synthetic dataset, these performance figures do not reflect production capabilities.</li>
            </ul>
          </div>

        </div>
      </div>
    </div>
  );
}
"""

if "export function AnalyticsView" not in text:
    text = text + "\n\n" + analytics_component

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
