import axios from "axios";

const apiClient = axios.create({
    baseURL: '/api', // nginx 프록시를 통해 gateway로 전달됨
    withCredentials: true,
});

// 저장된 토큰을 가져오는 함수
const getToken = () => localStorage.getItem('accessToken');

// HTTPOnly 쿠키를 사용하므로, 클라이언트에서 직접 토큰을 다루지 않습니다.
// 따라서 기존의 localStorage에서 토큰을 읽어 Authorization 헤더에 추가하는 인터셉터는 삭제합니다.
apiClient.interceptors.request.use((config) => {
    const token = getToken();
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});
apiClient.interceptors.response.use(
    (response) => {
        // 정상 응답이면 그대로 리턴
        return response;
    },
    async (error) => {
        const originalRequest = error.config;

        // 401(Unauthorized) 에러가 발생했고, 해당 요청이 재시도되지 않은 경우
        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;
            try {
                // 백엔드의 refresh 엔드포인트를 호출합니다.
                // HTTPOnly refresh 토큰은 브라우저가 자동으로 쿠키로 보내줍니다.
                const response = await apiClient.post(
                    "/api/users/refresh",
                    {},
                    { withCredentials: true }
                );
                const { accessToken } = response.data;

                // 새 액세스 토큰이 발급되면, 로컬 스토리지나 Redux에 저장해둡니다.
                localStorage.setItem("accessToken", accessToken);

                // 원래 요청의 헤더를 업데이트합니다.
                originalRequest.headers["Authorization"] = `Bearer ${accessToken}`;

                // 업데이트된 헤더로 원래의 요청을 재시도합니다.
                return apiClient(originalRequest);
            } catch (refreshError) {
                // refresh 토큰도 만료되거나 실패한 경우 (로그아웃 처리 등)
                return Promise.reject(refreshError);
            }
        }

        return Promise.reject(error);
    }
);

export default apiClient;
