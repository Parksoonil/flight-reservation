import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import '../style/BoardPage.css';
import apiClient from "../apiClient.jsx";

const BoardPage = () => {
    const [boards, setBoards] = useState([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        apiClient
            .get("api/boards")
            .then((response) => {
                const sortedBoards = response.data
                    .sort((a, b) => {
                        if (a.pinned === b.pinned) {
                            return new Date(b.createdDate) - new Date(a.createdDate);
                        }
                        return a.pinned ? -1 : 1;
                    });
                setBoards(sortedBoards);
                setLoading(false);
            })
            .catch((error) => {
                console.error("게시판 목록 가져오기 실패:", error);
                setLoading(false);
            });
    }, []);

    const handleBoardClick = (boardId) => {
        navigate(`/board/${boardId}`);
    };

    if (loading) {
        return <div className="loading">게시판을 불러오는 중...</div>;
    }

    return (
        <div className="board-page">
            <h1 className="page-title">공지사항</h1>
            <table className="board-table">
                <thead>
                <tr>
                    <th>작성일</th>
                    <th>제목</th>
                    <th>작성자</th>
                </tr>
                </thead>
                <tbody>
                {boards.length === 0 ? (
                    <tr>
                        <td colSpan="3" className="no-posts">최근 게시글이 없습니다.</td>
                    </tr>
                ) : (
                    boards.map((board) => (
                        <tr key={board.id} onClick={() => handleBoardClick(board.id)}>
                            <td>{new Date(board.createdDate).toLocaleDateString()}</td>
                            <td>{board.title}</td>
                            <td>{board.author}</td>
                        </tr>
                    ))
                )}
                </tbody>
            </table>
            <button className="write-button" onClick={() => navigate("/bwrite")}>글쓰기</button>
        </div>
    );
};

export default BoardPage;
