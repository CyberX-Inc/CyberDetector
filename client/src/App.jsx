import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import History from './pages/History';
import Layout from './components/Layout';
function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
export default App;
