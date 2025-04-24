import { createSlice } from '@reduxjs/toolkit';

const initialState = {
    // localStorage에서 토큰 대신 이메일이 있는지를 확인하여 로그인 상태를 결정합니다.
    isLoggedIn: !!localStorage.getItem("email"),
    email: localStorage.getItem("email") || null,
};

const authSlice = createSlice({
    name: 'auth',
    initialState,
    reducers: {
        login: (state, action) => {
            const { email } = action.payload;
            state.isLoggedIn = true;
            state.email = email;
            // HTTPOnly 쿠키를 사용하면 토큰은 서버가 관리하므로 localStorage에는 이메일만 저장합니다.
            localStorage.setItem("email", email);
        },
        logout: (state) => {
            state.isLoggedIn = false;
            state.email = null;
            localStorage.removeItem("email");
        },
    },
});

export const { login, logout } = authSlice.actions;
export default authSlice.reducer;