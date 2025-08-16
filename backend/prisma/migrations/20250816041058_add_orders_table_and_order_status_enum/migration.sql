/*
  Warnings:

  - You are about to drop the `payments` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE `payments` DROP FOREIGN KEY `payments_auction_id_fkey`;

-- DropForeignKey
ALTER TABLE `payments` DROP FOREIGN KEY `payments_user_id_fkey`;

-- AlterTable
ALTER TABLE `users` ADD COLUMN `wallet_balance` DECIMAL(19, 4) NOT NULL DEFAULT 0;

-- DropTable
DROP TABLE `payments`;

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

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `wallet_transactions` ADD CONSTRAINT `wallet_transactions_bid_id_fkey` FOREIGN KEY (`bid_id`) REFERENCES `bids`(`bid_id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `orders` ADD CONSTRAINT `orders_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `orders` ADD CONSTRAINT `orders_auction_id_fkey` FOREIGN KEY (`auction_id`) REFERENCES `auctions`(`auction_id`) ON DELETE CASCADE ON UPDATE CASCADE;
