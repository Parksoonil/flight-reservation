import './App.css'
import {Route, Routes} from "react-router-dom";
import MyPage from './pages/MyPage.jsx';
import Login from './pages/Login.jsx'

function App() {


  return (
      <div className="app-container">
              <div className="content">
                  <Routes>
                      <Route path="/login" element={<Login/>} />
                      <Route path="/mypage" element={<MyPage/>} />
                      {/* 기타 일반 페이지들 */}
                  </Routes>
              </div>
      </div>
  );
}

export default App
