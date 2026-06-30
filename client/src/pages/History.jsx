import { useEffect, useState } from 'react';
import { getHistory } from '../api';
function History() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await getHistory();
        setScans(data);
      } catch (err) {
        setError('Failed to load history');
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);
  if (loading) {
    return <div className="text-center text-gray-600">Loading history...</div>;
  }
  if (error) {
    return <div className="text-red-600 text-center">{error}</div>;
  }
  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-4">Scan History</h2>
      {scans.length === 0 ? (
        <p className="text-gray-500">No scans yet.</p>
      ) : (
        <div className="overflow-x-auto shadow ring-1 ring-black ring-opacity-5 rounded-lg">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Decision</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">API Results</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="px-6 py-4 text-sm text-gray-900 truncate max-w-xs">{scan.original_url}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{new Date(scan.timestamp).toLocaleString()}</td>
                  <td className="px-6 py-4 text-sm">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${scan.risk_score >= 60 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                      {scan.risk_score}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm capitalize">{scan.decision}</td>
                  <td className="px-6 py-4 text-sm">
                    <div className="flex flex-wrap gap-1">
                      {scan.virus_total_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">VT</span>}
                      {scan.google_safe_browsing_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">GSB</span>}
                      {scan.urlhaus_result === 'malicious' && <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs">URLhaus</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
export default History;
