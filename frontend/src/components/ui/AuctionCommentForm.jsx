import React from 'react';
import { PrimaryButton } from '@/components/ui/index.js';
import { IoSendOutline } from 'react-icons/io5';

export const AuctionCommentForm = ({ 
    comment, 
    setComment, 
    onSubmit, 
    isSubmitting, 
    placeholder = "Write your comment about this auction..." 
}) => {
    return (
        <div className="bg-white border border-gray-200 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Add Comment</h3>

            <form onSubmit={onSubmit} className="space-y-4">
                {/* Comment Text */}
                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                        Your comment
                    </label>
                    <textarea
                        value={comment}
                        onChange={(e) => setComment(e.target.value)}
                        placeholder={placeholder}
                        rows={4}
                        className="comment-textarea w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent resize-vertical"
                        required
                        minLength={1}
                        maxLength={500}
                    />
                    <p className={`comment-character-count text-xs mt-1 ${
                        comment.length > 450 ? 'error' : comment.length > 400 ? 'warning' : ''
                    }`}>
                        {comment.length}/500 characters
                    </p>
                </div>

                {/* Submit Button */}
                <div className="flex justify-end">
                    <PrimaryButton
                        type="submit"
                        disabled={isSubmitting || !comment.trim()}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-400 flex items-center gap-2"
                    >
                        {isSubmitting ? (
                            <>
                                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                Posting...
                            </>
                        ) : (
                            <>
                                <IoSendOutline size={16} />
                                Post Comment
                            </>
                        )}
                    </PrimaryButton>
                </div>
            </form>
        </div>
    );
};
