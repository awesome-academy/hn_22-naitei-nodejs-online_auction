import { useState, useEffect, useCallback } from 'react';
import { auctionCommentService } from '@/services/auctionComment.service.js';
import { useUser } from '@/contexts/UserContext.jsx';
import { useNotification } from '@/contexts/NotificationContext.jsx';

export const useAuctionComments = (auctionId) => {
    const { user } = useUser();
    const { showNotification } = useNotification();

    // State
    const [comments, setComments] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [pagination, setPagination] = useState({
        total: 0,
        page: 1,
        limit: 10
    });
    const [submitting, setSubmitting] = useState(false);
    const [newComment, setNewComment] = useState('');

    // Fetch comments
    const fetchComments = useCallback(async (page = 1, limit = 10) => {
        if (!auctionId) return;

        try {
            setLoading(true);
            setError(null);

            const response = await auctionCommentService.getCommentsByAuctionId(auctionId, page, limit);
            
            setComments(response.data || []);
            setPagination({
                total: response.total || 0,
                page: response.page || 1,
                limit: response.limit || 10
            });

        } catch (err) {
            setError(err.message || 'Failed to load comments');
            console.error('Error fetching auction comments:', err);
        } finally {
            setLoading(false);
        }
    }, [auctionId]);

    // Submit new comment
    const submitComment = async (e) => {
        e?.preventDefault();

        if (!user) {
            showNotification('Please login to comment', 'error');
            return;
        }

        if (!newComment.trim()) {
            showNotification('Please enter a comment', 'error');
            return;
        }

        if (!auctionId) {
            showNotification('Invalid auction ID', 'error');
            return;
        }

        try {
            setSubmitting(true);

            const commentData = {
                auctionId: auctionId,
                content: newComment.trim()
            };

            const response = await auctionCommentService.createComment(commentData);

            // Add new comment to the top of the list
            setComments(prev => [response, ...prev]);
            setPagination(prev => ({
                ...prev,
                total: prev.total + 1
            }));

            // Reset form
            setNewComment('');

            showNotification('Comment added successfully', 'success');
        } catch (err) {
            showNotification(err.message || 'Failed to add comment', 'error');
            console.error('Error creating auction comment:', err);
        } finally {
            setSubmitting(false);
        }
    };

    // Update comment
    const updateComment = async (commentId, content) => {
        if (!user) {
            showNotification('Please login to edit comments', 'error');
            return;
        }

        if (!content.trim()) {
            showNotification('Comment content cannot be empty', 'error');
            return;
        }

        try {
            const response = await auctionCommentService.updateComment(commentId, { content: content.trim() });

            // Update comment in local state
            setComments(prev =>
                prev.map(comment =>
                    comment.commentId === commentId ? response : comment
                )
            );

            showNotification('Comment updated successfully', 'success');
        } catch (err) {
            showNotification(err.message || 'Failed to update comment', 'error');
            console.error('Error updating auction comment:', err);
        }
    };

    // Delete comment
    const deleteComment = async (commentId) => {
        if (!user) {
            showNotification('Please login to delete comments', 'error');
            return;
        }

        if (!window.confirm('Are you sure you want to delete this comment?')) {
            return;
        }

        try {
            await auctionCommentService.deleteComment(commentId);

            // Remove comment from local state
            setComments(prev => prev.filter(comment => comment.commentId !== commentId));
            setPagination(prev => ({
                ...prev,
                total: Math.max(0, prev.total - 1)
            }));

            showNotification('Comment deleted successfully', 'success');
        } catch (err) {
            showNotification(err.message || 'Failed to delete comment', 'error');
            console.error('Error deleting auction comment:', err);
        }
    };

    // Load more comments (pagination)
    const loadMoreComments = async () => {
        const nextPage = pagination.page + 1;
        const hasMore = pagination.total > comments.length;

        if (!hasMore || loading) return;

        try {
            setLoading(true);
            const response = await auctionCommentService.getCommentsByAuctionId(auctionId, nextPage, pagination.limit);
            
            // Append new comments
            setComments(prev => [...prev, ...(response.data || [])]);
            setPagination(prev => ({
                ...prev,
                page: nextPage
            }));

        } catch (err) {
            showNotification(err.message || 'Failed to load more comments', 'error');
            console.error('Error loading more comments:', err);
        } finally {
            setLoading(false);
        }
    };

    // Check if user can modify comment
    const canModifyComment = (comment) => {
        if (!user || !comment) return false;
        return user.userId === comment.user?.userId || user.role === 'ADMIN';
    };

    // Calculate if there are more comments to load
    const hasMoreComments = pagination.total > comments.length;

    // Load initial comments when auctionId changes
    useEffect(() => {
        if (auctionId) {
            fetchComments();
        } else {
            setComments([]);
            setPagination({ total: 0, page: 1, limit: 10 });
        }
    }, [auctionId, fetchComments]);

    return {
        // Data
        comments,
        pagination,
        hasMoreComments,

        // Loading states
        loading,
        submitting,
        error,

        // Form state
        newComment,
        setNewComment,

        // Actions
        submitComment,
        updateComment,
        deleteComment,
        loadMoreComments,
        fetchComments,

        // Helpers
        canModifyComment
    };
};
