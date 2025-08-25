-- CreateTable
CREATE TABLE `users` (
    `user_id` CHAR(36) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('ADMIN', 'BIDDER', 'SELLER') NOT NULL,
    `is_banned` BOOLEAN NOT NULL DEFAULT false,
    `is_verified` BOOLEAN NOT NULL DEFAULT false,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,
    `warningCount` INTEGER NOT NULL DEFAULT 0,
    `wallet_balance` DECIMAL(19, 4) NOT NULL DEFAULT 0,

    UNIQUE INDEX `users_email_key`(`email`),
    PRIMARY KEY (`user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `wallet_transactions` (
    `transaction_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `transaction_type` ENUM('DEPOSIT', 'WITHDRAWAL', 'BID_PAYMENT', 'BID_REFUND', 'AUCTION_PAYMENT', 'ADMIN_ADJUSTMENT') NOT NULL,
    `transaction_status` ENUM('PENDING', 'SUCCESS', 'FAILED', 'CANCELLED') NOT NULL,
    `amount` DECIMAL(19, 4) NOT NULL,
    `balance_after` DECIMAL(19, 4) NOT NULL,
    `auction_id` CHAR(36) NULL,
    `bid_id` CHAR(36) NULL,
    `description` TEXT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    UNIQUE INDEX `wallet_transactions_bid_id_key`(`bid_id`),
    PRIMARY KEY (`transaction_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `warnings` (
    `warningId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `adminId` VARCHAR(191) NOT NULL,
    `reason` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`warningId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `follows` (
    `follow_id` CHAR(36) NOT NULL,
    `follower_id` CHAR(36) NOT NULL,
    `seller_id` CHAR(36) NOT NULL,
    `followed_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    UNIQUE INDEX `follows_follower_id_seller_id_key`(`follower_id`, `seller_id`),
    PRIMARY KEY (`follow_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `profiles` (
    `user_id` CHAR(36) NOT NULL,
    `full_name` VARCHAR(255) NULL,
    `phone_number` VARCHAR(255) NULL,
    `profile_image_url` VARCHAR(255) NULL,
    `created_at` TIMESTAMP(0) NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NULL,

    PRIMARY KEY (`user_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `addresses` (
    `address_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `street_address` VARCHAR(255) NOT NULL,
    `city` VARCHAR(255) NOT NULL,
    `state` VARCHAR(255) NULL,
    `postal_code` VARCHAR(255) NULL,
    `country` VARCHAR(255) NOT NULL,
    `address_type` ENUM('Home', 'Work', 'Others') NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`address_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `products` (
    `product_id` CHAR(36) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT NULL,
    `seller_id` CHAR(36) NOT NULL,
    `status` ENUM('ACTIVE', 'INACTIVE', 'SOLD', 'REMOVED', 'DELETING') NOT NULL DEFAULT 'INACTIVE',
    `stock_quantity` INTEGER NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`product_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `categories` (
    `category_id` CHAR(36) NOT NULL,
    `name` ENUM('ELECTRONICS', 'FASHION', 'COLLECTIBLES', 'HOME_APPLIANCES', 'SPORTS_EQUIPMENT', 'TOYS_AND_GAMES', 'VEHICLES', 'REAL_ESTATE', 'ART_AND_CRAFTS', 'JEWELRY_AND_ACCESSORIES', 'HEALTH_AND_BEAUTY', 'GARDEN_AND_OUTDOORS', 'MUSIC_INSTRUMENTS', 'PET_SUPPLIES', 'OFFICE_SUPPLIES') NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`category_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `products_categories` (
    `product_id` CHAR(36) NOT NULL,
    `category_id` CHAR(36) NOT NULL,

    PRIMARY KEY (`product_id`, `category_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `product_images` (
    `product_image_id` CHAR(36) NOT NULL,
    `product_id` CHAR(36) NOT NULL,
    `image_url` VARCHAR(255) NOT NULL,
    `is_primary` BOOLEAN NOT NULL DEFAULT false,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    PRIMARY KEY (`product_image_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `auctions` (
    `auction_id` CHAR(36) NOT NULL,
    `title` VARCHAR(255) NOT NULL,
    `seller_id` CHAR(36) NOT NULL,
    `start_time` TIMESTAMP(0) NOT NULL,
    `end_time` TIMESTAMP(0) NOT NULL,
    `current_price` DECIMAL(10, 2) NOT NULL,
    `starting_price` DECIMAL(10, 2) NOT NULL,
    `winner_id` CHAR(36) NULL,
    `status` ENUM('PENDING', 'READY', 'OPEN', 'CLOSED', 'CANCELED', 'COMPLETED', 'EXTENDED', 'REFUND') NOT NULL DEFAULT 'PENDING',
    `cancel_reason` TEXT NULL,
    `minimum_bid_increment` DECIMAL(10, 2) NOT NULL,
    `last_bid_time` TIMESTAMP(0) NOT NULL,
    `bid_count` BIGINT NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`auction_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `auction_products` (
    `auction_product_id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `product_id` CHAR(36) NOT NULL,
    `quantity` INTEGER NOT NULL DEFAULT 1,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    UNIQUE INDEX `auction_products_auction_id_product_id_key`(`auction_id`, `product_id`),
    PRIMARY KEY (`auction_product_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `bids` (
    `bid_id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `bid_amount` DECIMAL(19, 4) NOT NULL,
    `isHidden` BOOLEAN NOT NULL DEFAULT false,
    `status` ENUM('PENDING', 'VALID', 'INVALID') NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    PRIMARY KEY (`bid_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `chat_rooms` (
    `chat_room_id` CHAR(36) NOT NULL,
    `user1_id` CHAR(36) NOT NULL,
    `user2_id` CHAR(36) NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,
    `deleted_by_user1` BOOLEAN NOT NULL DEFAULT false,
    `deleted_by_user2` BOOLEAN NOT NULL DEFAULT false,
    `user1_deleted_at` TIMESTAMP(0) NULL,
    `user2_deleted_at` TIMESTAMP(0) NULL,

    UNIQUE INDEX `chat_rooms_user1_id_user2_id_key`(`user1_id`, `user2_id`),
    PRIMARY KEY (`chat_room_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `messages` (
    `message_id` CHAR(36) NOT NULL,
    `chat_room_id` CHAR(36) NOT NULL,
    `sender_id` CHAR(36) NOT NULL,
    `content` TEXT NULL,
    `file_url` VARCHAR(255) NULL,
    `type` ENUM('TEXT', 'IMAGE', 'FILE', 'SYSTEM') NOT NULL DEFAULT 'TEXT',
    `status` ENUM('SENT', 'DELIVERED', 'READ') NOT NULL DEFAULT 'SENT',
    `timestamp` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `version` INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (`message_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `watchlists` (
    `watchlist_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `added_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    UNIQUE INDEX `watchlists_user_id_auction_id_key`(`user_id`, `auction_id`),
    PRIMARY KEY (`watchlist_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `notifications` (
    `notification_id` CHAR(36) NOT NULL,
    `message` TEXT NOT NULL,
    `is_read` BOOLEAN NOT NULL DEFAULT false,
    `user_id` CHAR(36) NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,
    `metadata` JSON NULL,

    PRIMARY KEY (`notification_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `product_comments` (
    `comment_id` CHAR(36) NOT NULL,
    `product_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `content` TEXT NOT NULL,
    `rating` INTEGER NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`comment_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `orders` (
    `id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `total_amount` DECIMAL(19, 4) NOT NULL,
    `status` ENUM('PENDING', 'PAID', 'SHIPPING', 'COMPLETED', 'CANCELED') NOT NULL DEFAULT 'PENDING',
    `payment_due_date` TIMESTAMP(0) NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `shippings` (
    `id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `seller_id` CHAR(36) NOT NULL,
    `buyer_id` CHAR(36) NOT NULL,
    `shipping_status` ENUM('PENDING', 'SHIPPED', 'IN_TRANSIT', 'DELIVERED') NOT NULL DEFAULT 'PENDING',
    `price` DECIMAL(19, 4) NULL,
    `tracking_number` VARCHAR(100) NULL,
    `shipped_at` TIMESTAMP(0) NULL,
    `estimated_delivery` TIMESTAMP(0) NULL,
    `actual_delivery` TIMESTAMP(0) NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_bid_id_fkey` FOREIGN KEY (`bid_id`) REFERENCES `bids`(`bid_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `warnings` ADD CONSTRAINT `warnings_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `warnings` ADD CONSTRAINT `warnings_adminId_fkey` FOREIGN KEY (`adminId`) REFERENCES `users`(`user_id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `follows` ADD CONSTRAINT `follows_follower_id_fkey` FOREIGN KEY (`follower_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `follows` ADD CONSTRAINT `follows_seller_id_fkey` FOREIGN KEY (`seller_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `profiles` ADD CONSTRAINT `profiles_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `addresses` ADD CONSTRAINT `addresses_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `products` ADD CONSTRAINT `products_seller_id_fkey` FOREIGN KEY (`seller_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `products_categories` ADD CONSTRAINT `products_categories_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `products_categories` ADD CONSTRAINT `products_categories_category_id_fkey` FOREIGN KEY (`category_id`) REFERENCES `categories`(`category_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `product_images` ADD CONSTRAINT `product_images_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `auctions` ADD CONSTRAINT `auctions_seller_id_fkey` FOREIGN KEY (`seller_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `auctions` ADD CONSTRAINT `auctions_winner_id_fkey` FOREIGN KEY (`winner_id`) REFERENCES `users`(`user_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `auction_products` ADD CONSTRAINT `auction_products_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `auction_products` ADD CONSTRAINT `auction_products_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bids` ADD CONSTRAINT `bids_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bids` ADD CONSTRAINT `bids_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `chat_rooms` ADD CONSTRAINT `chat_rooms_user1_id_fkey` FOREIGN KEY (`user1_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `chat_rooms` ADD CONSTRAINT `chat_rooms_user2_id_fkey` FOREIGN KEY (`user2_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `messages` ADD CONSTRAINT `messages_chat_room_id_fkey` FOREIGN KEY (`chat_room_id`) REFERENCES `chat_rooms`(`chat_room_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `messages` ADD CONSTRAINT `messages_sender_id_fkey` FOREIGN KEY (`sender_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `watchlists` ADD CONSTRAINT `watchlists_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `watchlists` ADD CONSTRAINT `watchlists_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `notifications` ADD CONSTRAINT `notifications_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `product_comments` ADD CONSTRAINT `product_comments_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `product_comments` ADD CONSTRAINT `product_comments_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `orders` ADD CONSTRAINT `orders_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `orders` ADD CONSTRAINT `orders_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `shippings` ADD CONSTRAINT `shippings_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `shippings` ADD CONSTRAINT `shippings_seller_id_fkey` FOREIGN KEY (`seller_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `shippings` ADD CONSTRAINT `shippings_buyer_id_fkey` FOREIGN KEY (`buyer_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;
