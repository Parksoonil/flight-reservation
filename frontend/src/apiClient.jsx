import axios from "axios";

const apiClient = axios.create({
    baseURL: "http://localhost:8443",
    withCredentials: true, // HTTPOnly 쿠키와 자격증명을 포함시킵니다.
});

// HTTPOnly 쿠키를 사용하므로, 클라이언트에서 직접 토큰을 다루지 않습니다.
// 따라서 기존의 localStorage에서 토큰을 읽어 Authorization 헤더에 추가하는 인터셉터는 삭제합니다.
apiClient.interceptors.request.use((config) => {
    // 별도로 헤더를 조작할 필요가 없으므로 그대로 config를 반환합니다.
    return config;
});

export default apiClient;
