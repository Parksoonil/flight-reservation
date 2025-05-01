import React, { useState, useEffect } from "react";
import axios from "axios";
import { useParams, useNavigate } from "react-router-dom";
import '../style/BoardDetail.css';
import apiClient from "../apiClient.jsx";

const BoardDetail = () => {
  const [board, setBoard] = useState(null);
  const [loading, setLoading] = useState(true);
  const { boardId } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    const fetchBoard = async () => {
      try {
        const response = await apiClient.get(`api/boards/${boardId}`);
        const currentBoard = response.data;

        await apiClient.put(`api/boards/${boardId}`, {
          ...currentBoard,
          views: currentBoard.views + 1,
        });

        setBoard({
          ...currentBoard,
          views: currentBoard.views + 1,
        });
        setLoading(false);
      } catch (error) {
        console.error("게시판 가져오기 실패:", error);
        setLoading(false);
      }
    };

    fetchBoard();
  }, [boardId]);

  if (loading) {
    return <div>게시글을 불러오는 중...</div>;
  }

  if (!board) {
    return <div>게시글을 찾을 수 없습니다.</div>;
  }

  return (
    <div className="board-detail-container">
      <h1 className="board-detail-title">{board.title}</h1>
      <div className="board-detail-content">
        <div className="content-box">
          <p>{board.content}</p>
        </div>
      </div>
      <div className="board-detail-meta">
        <div className="board-detail-m">
        <p><strong>작성자:</strong> {board.author}</p>
        <p><strong>작성일:</strong> {new Date(board.createdDate).toLocaleString()}</p>
        </div>
      </div>
      <button className="back-to-board-btn" onClick={() => navigate("/board")}>목록으로</button>
    </div>
  );
};

export default BoardDetail;
