import { useState } from 'react';
import { protectUrl } from '../api';

function Home() {
  const [url, setUrl] = useState('');
  const [protectedUrl, setProtectedUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setProtectedUrl('');
    try {
      const data = await protectUrl(url);
      setProtectedUrl(data.protectedUrl);
    } catch (err) {
      setError(err.message); // err is already a string from api.js
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-3xl font-bold text-gray-900 mb-4">Protect a URL</h1>
      <p className="text-gray-600 mb-6">
        Enter a link to generate a protected URL that will be scanned for threats before redirecting.
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="url" className="block text-sm font-medium text-gray-700">Destination URL</label>
          <input
            type="url"
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
        >
          {loading ? 'Generating...' : 'Generate Protected Link'}
        </button>
      </form>

      {error && (
        <div className="mt-4 text-red-600 text-sm bg-red-50 border border-red-200 rounded-md p-3">
          {error}
        </div>
      )}

      {protectedUrl && (
        <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-md">
          <p className="text-sm font-medium text-green-800">Protected URL:</p>
          <div className="mt-1 flex items-center justify-between">
            <code className="text-sm bg-white px-3 py-2 rounded border border-gray-200 flex-1 mr-2 overflow-x-auto">
              {protectedUrl}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(protectedUrl)}
              className="text-indigo-600 hover:text-indigo-800 text-sm font-medium"
            >
              Copy
            </button>
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Anyone opening this link will be scanned for threats.
          </p>
        </div>
      )}
    </div>
  );
}

export default Home;
