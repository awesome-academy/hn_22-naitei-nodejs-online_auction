import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { userService } from '@/services/user.service';
import { productService } from '@/services/product.service';
import { followService } from '@/services/follow.service';
import { useUser } from '@/contexts/UserContext';
import { useNotification } from '@/contexts/NotificationContext';
import { Layout } from '@/components/layout/Layout';
import { Container, Title, PrimaryButton, LoadingSpinner } from '@/components/ui/index.js';

const SellerProfile = () => {
    const { sellerId } = useParams();
    const navigate = useNavigate();
    const { user } = useUser();
    const { showNotification } = useNotification();

    const [sellerInfo, setSellerInfo] = useState(null);
    const [products, setProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [productsLoading, setProductsLoading] = useState(true);
    const [followLoading, setFollowLoading] = useState(false);
    const [isFollowing, setIsFollowing] = useState(false);
    const [followerCount, setFollowerCount] = useState(0);

    useEffect(() => {
        if (sellerId) {
            fetchSellerData();
        }
    }, [sellerId]);

    const fetchSellerData = async () => {
        setLoading(true);
        setProductsLoading(true);
        try {
            // Fetch seller profile, products, and follow status in parallel
            const [sellerResponse, productsResponse, followCountResponse] = await Promise.all([
                userService.getUserAccountInfo(sellerId),
                productService.getUserActiveProducts(sellerId),
                followService.getFollowCount(sellerId)
            ]);

            setSellerInfo(sellerResponse);
            setProducts(productsResponse.products || []);
            setFollowerCount(followCountResponse.followerCount || 0);

            // Check follow status if user is logged in and is a bidder
            if (user && user.role === 'BIDDER') {
                try {
                    const followStatusResponse = await followService.checkFollowStatus(sellerId);
                    setIsFollowing(followStatusResponse.isFollowedByCurrentUser);
                } catch (error) {
                    console.log('Could not check follow status:', error);
                }
            }
        } catch (error) {
            console.error('Error fetching seller data:', error);
            showNotification('Failed to load seller profile', 'error');
        } finally {
            setLoading(false);
            setProductsLoading(false);
        }
    };

    const handleFollowToggle = async () => {
        if (!user || user.role !== 'BIDDER') {
            showNotification('Only bidders can follow sellers', 'error');
            return;
        }

        setFollowLoading(true);
        try {
            if (isFollowing) {
                await followService.unfollowSeller(sellerId);
                setIsFollowing(false);
                setFollowerCount(prev => prev - 1);
                showNotification('Successfully unfollowed seller', 'success');
            } else {
                await followService.followSeller(sellerId);
                setIsFollowing(true);
                setFollowerCount(prev => prev + 1);
                showNotification('Successfully followed seller', 'success');
            }
        } catch (error) {
            console.error('Error toggling follow:', error);
            showNotification(error.message || 'Failed to update follow status', 'error');
        } finally {
            setFollowLoading(false);
        }
    };

    const handleProductClick = (productId) => {
        navigate(`/products/${productId}`);
    };

    if (loading) {
        return (
            <Layout>
                <LoadingSpinner text="Loading seller profile..." />
            </Layout>
        );
    }

    if (!sellerInfo) {
        return (
            <Layout>
                <Container className="py-8">
                    <div className="text-center">
                        <Title level={2} className="text-gray-900 mb-4">Seller not found</Title>
                        <p className="text-gray-600 mb-6">The seller you're looking for doesn't exist.</p>
                        <PrimaryButton
                            onClick={() => navigate('/dashboard')}
                            className="px-8 py-3"
                        >
                            Back to Dashboard
                        </PrimaryButton>
                    </div>
                </Container>
            </Layout>
        );
    }

    const profile = sellerInfo.profile?.[0];

    return (
        <Layout>
            <Container className="py-8">
                {/* Back Button */}
                <div className="mb-6">
                    <button
                        onClick={() => navigate(-1)}
                        className="flex items-center text-gray-600 hover:text-green transition-colors"
                    >
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                        Back
                    </button>
                </div>

                <Title level={2} className="text-gray-900 mb-8">Seller Profile</Title>

                {/* Seller Info Card */}
                <div className="bg-white rounded-lg shadow-lg p-8 mb-8">
                    <div className="flex flex-col lg:flex-row items-start space-y-6 lg:space-y-0 lg:space-x-8">
                        {/* Avatar */}
                        <div className="flex-shrink-0 self-center lg:self-start">
                            <div className="w-32 h-32 bg-gray-200 rounded-full flex items-center justify-center overflow-hidden border-4 border-gray-100">
                                {profile?.profileImageUrl ? (
                                    <img
                                        src={profile.profileImageUrl}
                                        alt={profile.fullName || 'Seller'}
                                        className="w-full h-full object-cover"
                                    />
                                ) : (
                                    <svg className="w-16 h-16 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
                                    </svg>
                                )}
                            </div>
                        </div>

                        {/* Seller Details */}
                        <div className="flex-1 text-center lg:text-left">
                            <Title level={3} className="text-gray-900 mb-4">
                                {profile?.fullName || 'Unknown Seller'}
                            </Title>

                            <div className="flex flex-wrap justify-center lg:justify-start items-center gap-6 text-sm text-gray-600 mb-6">
                                <div className="flex items-center bg-gray-50 px-3 py-2 rounded-lg">
                                    <svg className="w-4 h-4 mr-2 text-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                    </svg>
                                    <span className="font-medium">{followerCount} followers</span>
                                </div>

                                {sellerInfo.stats && (
                                    <div className="flex items-center bg-gray-50 px-3 py-2 rounded-lg">
                                        <svg className="w-4 h-4 mr-2 text-green" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z" />
                                        </svg>
                                        <span className="font-medium">{sellerInfo.stats.totalProductsSold || 0} products sold</span>
                                    </div>
                                )}
                            </div>

                            {profile?.phoneNumber && (
                                <div className="flex justify-center lg:justify-start items-center text-gray-600 mb-6">
                                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                    </svg>
                                    <span>{profile.phoneNumber}</span>
                                </div>
                            )}

                            {/* Follow Button */}
                            {user && user.role === 'BIDDER' && user.id !== sellerId && (
                                <div className="flex justify-center lg:justify-start">
                                    {isFollowing ? (
                                        <button
                                            onClick={handleFollowToggle}
                                            disabled={followLoading}
                                            className="px-6 py-3 bg-gray-200 text-gray-800 rounded-full font-medium hover:bg-gray-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                                        >
                                            {followLoading ? (
                                                <>
                                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></div>
                                                    Loading...
                                                </>
                                            ) : (
                                                <>
                                                    <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                                    </svg>
                                                    Following
                                                </>
                                            )}
                                        </button>
                                    ) : (
                                        <PrimaryButton
                                            onClick={handleFollowToggle}
                                            disabled={followLoading}
                                            className="px-8 py-3 flex items-center"
                                        >
                                            {followLoading ? (
                                                <>
                                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></div>
                                                    Loading...
                                                </>
                                            ) : (
                                                <>
                                                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                                    </svg>
                                                    Follow
                                                </>
                                            )}
                                        </PrimaryButton>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Products Section */}
                <div className="mb-8">
                    <Title text="Active Products" className="mb-6" />

                    {productsLoading ? (
                        <div className="flex justify-center items-center py-12">
                            <LoadingSpinner />
                        </div>
                    ) : products.length === 0 ? (
                        <div className="text-center py-12">
                            <div className="mb-4">
                                <svg className="w-16 h-16 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                                </svg>
                            </div>
                            <h4 className="text-lg font-medium text-gray-900 mb-2">No products available</h4>
                            <p className="text-gray-600">This seller doesn't have any active products at the moment.</p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                            {products.map((product) => (
                                <div
                                    key={product.productId}
                                    onClick={() => handleProductClick(product.productId)}
                                    className="bg-white border border-gray-200 rounded-lg shadow-sm hover:shadow-md transition-shadow cursor-pointer group"
                                >
                                    {/* Product Image */}
                                    <div className="aspect-square overflow-hidden rounded-t-lg bg-gray-100">
                                        {product.images && product.images.length > 0 ? (
                                            <img
                                                src={product.images.find(img => img.isPrimary)?.imageUrl || product.images[0].imageUrl}
                                                alt={product.name}
                                                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                                            />
                                        ) : (
                                            <div className="w-full h-full flex items-center justify-center">
                                                <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                                </svg>
                                            </div>
                                        )}
                                    </div>

                                    {/* Product Info */}
                                    <div className="p-4">
                                        <h4 className="font-semibold text-gray-900 mb-2 line-clamp-2">{product.name}</h4>
                                        {product.description && (
                                            <p className="text-sm text-gray-600 mb-3 line-clamp-2">{product.description}</p>
                                        )}
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-gray-500">Stock: {product.stockQuantity}</span>
                                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${product.status === 'ACTIVE'
                                                ? 'bg-green-100 text-green-800'
                                                : 'bg-gray-100 text-gray-800'
                                                }`}>
                                                {product.status}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </Container>
        </Layout>
    );
};

export default SellerProfile;
