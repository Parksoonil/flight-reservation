import { createSlice } from '@reduxjs/toolkit';

const initialState = {
    isLoggedIn: !!localStorage.getItem("token"),
    email: localStorage.getItem("email") || null,
};

const authSlice = createSlice({
    name: 'auth',
    initialState,
    reducers: {
        login: (state, action) => {
            const { email, token } = action.payload;
            state.isLoggedIn = true;
            state.email = email;
            localStorage.setItem("token", token);
            localStorage.setItem("email", email);
        },
        logout: (state) => {
            state.isLoggedIn = false;
            state.email = null;
            localStorage.removeItem("token");
            localStorage.removeItem("email");
        },
    },
});

export const { login, logout } = authSlice.actions;
export default authSlice.reducer;
