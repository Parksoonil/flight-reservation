import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import '../style/BoardWrite.css';
import apiClient from "../apiClient.jsx";

const BoardWrite = () => {
    const [title, setTitle] = useState("");
    const [content, setContent] = useState("");
    const [author, setAuthor] = useState("");
    const [pinned, setPinned] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = (e) => {
        e.preventDefault();

        const newBoard = {
            title,
            content,
            author,
            createdDate: new Date().toISOString(),
            pinned,
        };

        apiClient
            .post("api/boards", newBoard)
            .then(() => {
                setTitle("");
                setContent("");
                setAuthor("");
                setPinned(false);
                navigate("/board");
            })
            .catch((error) => {
                console.error("게시판 작성 실패:", error);
                alert("게시판 작성 중 오류가 발생했습니다.");
            });
    };

    return (
        <div className="board-write-container">
            <h1 className="board-write-title">게시글 작성</h1>
            <form className="board-write-form" onSubmit={handleSubmit}>
                <div className="form-group">
                    <label className="form-label">제목:</label>
                    <input
                        className="form-input"
                        type="text"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        required
                    />
                </div>
                <div className="form-group">
                    <label className="form-label">내용:</label>
                    <textarea
                        className="form-textarea"
                        value={content}
                        onChange={(e) => setContent(e.target.value)}
                        required
                    ></textarea>
                </div>
                <div className="form-group">
                    <label className="form-label">글쓴이:</label>
                    <input
                        className="form-input"
                        type="text"
                        value={author}
                        onChange={(e) => setAuthor(e.target.value)}
                        required
                    />
                </div>
                <div className="form-group">
                    <label className="form-label">
                        상단 고정:
                        <input
                            className="form-checkbox"
                            type="checkbox"
                            checked={pinned}
                            onChange={() => setPinned(!pinned)}
                        />
                    </label>
                </div>
                <div className="form-buttons">
                    <button className="form-button-submit" type="submit">작성하기</button>
                    <button className="form-button-cancel" type="button" onClick={() => navigate("/board")}>목록으로</button>
                </div>
            </form>
        </div>
    );
};

export default BoardWrite;
