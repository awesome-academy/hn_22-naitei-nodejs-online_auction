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

    UNIQUE INDEX `users_email_key`(`email`),
    PRIMARY KEY (`user_id`)
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
    `auction_id` CHAR(36) NULL,

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
    `start_time` TIMESTAMP(0) NOT NULL,
    `end_time` TIMESTAMP(0) NOT NULL,
    `current_price` DECIMAL(10, 2) NOT NULL,
    `starting_price` DECIMAL(10, 2) NOT NULL,
    `winner_id` CHAR(36) NULL,
    `status` ENUM('PENDING', 'READY', 'OPEN', 'CLOSED', 'CANCELED', 'COMPLETED', 'EXTENDED') NOT NULL DEFAULT 'PENDING',
    `minimum_bid_increment` DECIMAL(10, 2) NOT NULL,
    `last_bid_time` TIMESTAMP(0) NOT NULL,
    `bid_count` BIGINT NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),
    `updated_at` TIMESTAMP(0) NOT NULL,

    PRIMARY KEY (`auction_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `bids` (
    `bid_id` CHAR(36) NOT NULL,
    `auction_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `bid_amount` DECIMAL(19, 4) NOT NULL,
    `status` ENUM('PENDING', 'VALID', 'INVALID') NOT NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    PRIMARY KEY (`bid_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `payments` (
    `auction_id` CHAR(36) NOT NULL,
    `user_id` CHAR(36) NOT NULL,
    `amount` DECIMAL(19, 4) NOT NULL,
    `payment_method` ENUM('VNPAY') NOT NULL,
    `status` ENUM('PENDING', 'SUCCESS', 'FAILED') NOT NULL,
    `bank_code` VARCHAR(255) NULL,
    `payment_date` TIMESTAMP(0) NULL,
    `created_at` TIMESTAMP(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0),

    PRIMARY KEY (`auction_id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

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
ALTER TABLE `products` ADD CONSTRAINT `products_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `products_categories` ADD CONSTRAINT `products_categories_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `products_categories` ADD CONSTRAINT `products_categories_category_id_fkey` FOREIGN KEY (`category_id`) REFERENCES `categories`(`category_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `product_images` ADD CONSTRAINT `product_images_product_id_fkey` FOREIGN KEY (`product_id`) REFERENCES `products`(`product_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `auctions` ADD CONSTRAINT `auctions_winner_id_fkey` FOREIGN KEY (`winner_id`) REFERENCES `users`(`user_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bids` ADD CONSTRAINT `bids_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `bids` ADD CONSTRAINT `bids_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `payments` ADD CONSTRAINT `payments_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `payments` ADD CONSTRAINT `payments_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;
