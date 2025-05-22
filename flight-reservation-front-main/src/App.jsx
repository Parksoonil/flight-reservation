import {useDispatch} from "react-redux";
import {useEffect} from "react";
import {jwtDecode} from "jwt-decode";
import ScrollTop from "./components/ScrollTop.jsx";
import RouteSetup from "./routes/RouteSetup.jsx";
import {login, logout} from "./store/authSlice.js";
import apiClient from "./apiClient.jsx";
import "./App.css"


function App() {
  const dispatch = useDispatch();

  
  // 인증 및 자동 로그인 처리
  useEffect(() => {
    const token = localStorage.getItem("accessToken");
    if (token) {
      try {
        const decoded = jwtDecode(token);
        const expTime = decoded.exp * 1000;
        if (Date.now() < expTime) {
          dispatch(login({ email: decoded.sub, accessToken: token, user: decoded }));
        } else {
          apiClient.post("/api/users/refresh", {}, { withCredentials: true })
            .then((response) => {
              const { accessToken: newAccessToken } = response.data;
              localStorage.setItem("accessToken", newAccessToken);
              const newDecoded = jwtDecode(newAccessToken);
              dispatch(login({ email: newDecoded.sub, accessToken: newAccessToken, user: newDecoded }));
            })
            .catch((error) => {
              console.error("토큰 재발급 실패", error);
              dispatch(logout());
            });
        }
      } catch (error) {
        console.error("토큰 디코딩 실패", error);
      }
    }
  }, [dispatch]);

  return (
    <div>
      <div>
        <ScrollTop />
        <RouteSetup />
      </div>
    </div>
  );
}

export default App;
