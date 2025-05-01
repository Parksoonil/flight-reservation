import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "../style/Boards.css";
import apiClient from "../apiClient.jsx";

const Boards = () => {
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
          })
          .slice(0, 5);

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

  const handleMorePostClick = () => {
    navigate("/board");
  };

  return (
      <div className="recent-boards">
          <div className="recent-boards-header-container">
              <h1 className="recent-boards-header">공지사항</h1>
              <button className="more-post-button" onClick={handleMorePostClick}>+</button>
          </div>

          {loading ? (
              <div className="board-page-loading">게시글을 불러오는 중...</div>
          ) : (
              <table className="boards-table">
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
                          <td colSpan="3">최근 게시글이 없습니다.</td>
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
          )}
      </div>
  );
};

export default Boards;
