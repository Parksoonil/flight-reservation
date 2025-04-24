import React, { useState } from 'react';
import apiClient from "../apiClient.jsx";
import { useDispatch } from "react-redux";
import {login} from "../store/authSlice.js";

function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const dispatch = useDispatch();

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            // withCredentials 옵션을 활성화하여 HTTPOnly 쿠키가 Set-Cookie 헤더를 통해 전달될 수 있도록 합니다.
            const res = await apiClient.post(
                'api/users/login',
                { email, password },
                { withCredentials: true }  // 서버와 클라이언트가 동일 도메인 혹은 CORS 설정을 갖추어야 합니다.
            );

            // HTTPOnly 쿠키에 토큰이 이미 설정되었으므로, 응답에는 사용자 정보만 필요합니다.
            const { user } = res.data;

            // Redux 로그인 액션에서는 토큰 정보를 따로 저장하지 않고, 사용자 정보만 저장할 수 있습니다.
            dispatch(login({ email: user.email, user }));

            alert('로그인 성공');
        } catch (err) {
            console.error("로그인 오류", err);
            setError("이메일 또는 비밀번호를 확인해 주세요");
        }
    };

    return (
        <section className="bg-gray-50 dark:bg-gray-900 min-h-screen">
            <div className="flex flex-col items-center justify-center px-6 py-8 mx-auto md:h-screen lg:py-0">
                <a href="/" className="flex items-center mb-6 text-2xl font-semibold text-gray-900 dark:text-white">
                    <img className="w-8 h-8 mr-2" src="https://flowbite.s3.amazonaws.com/blocks/marketing-ui/logo.svg" alt="logo" />
                    YS FLIGHT
                </a>
                <div className="w-full bg-white rounded-lg shadow dark:border md:mt-0 sm:max-w-md xl:p-0 dark:bg-gray-800 dark:border-gray-700">
                    <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
                        <h1 className="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl dark:text-white">
                            로그인
                        </h1>
                        {error && (
                            <div className="text-red-500 text-sm">
                                {error}
                            </div>
                        )}
                        <form className="space-y-4 md:space-y-6" onSubmit={handleLogin}>
                            <div>
                                <label htmlFor="email" className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                    이메일
                                </label>
                                <input
                                    type="email"
                                    id="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="bg-gray-50 border border-gray-300 text-gray-900 rounded-lg block w-full p-2.5 focus:ring-primary-600 focus:border-primary-600 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white"
                                    placeholder="name@example.com"
                                    required
                                />
                            </div>
                            <div>
                                <label htmlFor="password" className="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                    비밀번호
                                </label>
                                <input
                                    type="password"
                                    id="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                    className="bg-gray-50 border border-gray-300 text-gray-900 rounded-lg block w-full p-2.5 focus:ring-primary-600 focus:border-primary-600 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white"
                                    required
                                />
                            </div>
                            <button
                                type="submit"
                                className="w-full text-white bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
                            >
                                로그인
                            </button>
                            <p className="text-sm font-light text-gray-500 dark:text-gray-400">
                                계정이 없으신가요?{" "}
                                <a
                                    href="/register"
                                    className="font-medium text-blue-600 hover:underline dark:text-blue-500"
                                >
                                    회원가입
                                </a>
                            </p>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    );
}

export default Login;
