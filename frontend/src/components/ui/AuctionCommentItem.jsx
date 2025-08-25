import React, { useState } from 'react';
import { useUser } from '@/contexts/UserContext.jsx';
import { IoTrashOutline, IoCreateOutline, IoSaveOutline, IoCloseOutline } from 'react-icons/io5';

export const AuctionCommentItem = ({ comment, onDelete, onEdit }) => {
    const { user } = useUser();
    const [isEditing, setIsEditing] = useState(false);
    const [editContent, setEditContent] = useState(comment.content);

    const canModifyComment = user && (user.userId === comment.user?.userId || user.role === 'ADMIN');

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return new Intl.DateTimeFormat('vi-VN', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }).format(date);
    };

    const handleDelete = () => {
        if (window.confirm('Are you sure you want to delete this comment?')) {
            onDelete(comment.commentId);
        }
    };

    const handleSaveEdit = () => {
        if (editContent.trim() && editContent !== comment.content) {
            onEdit(comment.commentId, editContent.trim());
        }
        setIsEditing(false);
    };

    const handleCancelEdit = () => {
        setEditContent(comment.content);
        setIsEditing(false);
    };

    const getUserDisplayName = () => {
        if (comment.user?.profile?.firstName || comment.user?.profile?.lastName) {
            return `${comment.user.profile.firstName || ''} ${comment.user.profile.lastName || ''}`.trim();
        }
        // Fallback to userId if no profile name is available
        return comment.user?.userId ? `User ${comment.user.userId.slice(-4)}` : 'Anonymous User';
    };

    const getUserAvatar = () => {
        return comment.user?.profile?.avatar;
    };

    return (
        <div className="comment-item border-b border-gray-200 pb-4 last:border-b-0">
            <div className="flex items-start space-x-3">
                {/* User Avatar */}
                <div className="flex-shrink-0">
                    {getUserAvatar() ? (
                        <img
                            src={getUserAvatar()}
                            alt={getUserDisplayName()}
                            className="comment-avatar w-10 h-10 rounded-full object-cover"
                        />
                    ) : (
                        <div className="comment-avatar w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                            <span className="text-gray-600 font-medium text-sm">
                                {getUserDisplayName().charAt(0)?.toUpperCase() || 'U'}
                            </span>
                        </div>
                    )}
                </div>

                {/* Comment Content */}
                <div className="flex-1 min-w-0">
                    <div className="comment-header flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                            <span className="comment-user-name font-medium text-gray-900">
                                {getUserDisplayName()}
                            </span>
                        </div>

                        {/* Action Buttons */}
                        {canModifyComment && !isEditing && (
                            <div className="comment-actions flex items-center space-x-1">
                                <button
                                    onClick={() => setIsEditing(true)}
                                    className="p-1 text-gray-400 hover:text-blue-600 transition-colors"
                                    title="Edit comment"
                                >
                                    <IoCreateOutline size={16} />
                                </button>
                                <button
                                    onClick={handleDelete}
                                    className="p-1 text-gray-400 hover:text-red-600 transition-colors"
                                    title="Delete comment"
                                >
                                    <IoTrashOutline size={16} />
                                </button>
                            </div>
                        )}

                        {/* Edit Actions */}
                        {isEditing && (
                            <div className="flex items-center space-x-1">
                                <button
                                    onClick={handleSaveEdit}
                                    className="p-1 text-gray-400 hover:text-green-600 transition-colors"
                                    title="Save changes"
                                    disabled={!editContent.trim()}
                                >
                                    <IoSaveOutline size={16} />
                                </button>
                                <button
                                    onClick={handleCancelEdit}
                                    className="p-1 text-gray-400 hover:text-red-600 transition-colors"
                                    title="Cancel editing"
                                >
                                    <IoCloseOutline size={16} />
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Comment Content */}
                    {isEditing ? (
                        <div className="mt-2">
                            <textarea
                                value={editContent}
                                onChange={(e) => setEditContent(e.target.value)}
                                className="comment-textarea w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent resize-vertical"
                                rows={3}
                                maxLength={500}
                                required
                            />
                            <p className={`comment-character-count text-xs mt-1 ${
                                editContent.length > 450 ? 'error' : editContent.length > 400 ? 'warning' : ''
                            }`}>
                                {editContent.length}/500 characters
                            </p>
                        </div>
                    ) : (
                        <p className="comment-content text-gray-700 text-sm mb-2 whitespace-pre-wrap">
                            {comment.content}
                        </p>
                    )}

                    <div className="comment-meta flex items-center justify-between">
                        <span className="comment-date text-xs text-gray-500">
                            {formatDate(comment.createdAt)}
                        </span>
                        {comment.updatedAt && comment.updatedAt !== comment.createdAt && (
                            <span className="comment-edit-badge text-xs text-gray-400 italic">
                                (edited)
                            </span>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};
