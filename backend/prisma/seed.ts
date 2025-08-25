import { PrismaClient, Role, CategoryType, ProductStatus, AuctionStatus, OrderStatus, ShippingStatus, BidStatus, TransactionType, TransactionStatus, AddressType } from '@prisma/client'
import { Decimal } from '@prisma/client/runtime/library'
import * as bcrypt from 'bcrypt'

const prisma = new PrismaClient()

async function main() {
  console.log('🌱 Starting seed...')

  // Clear existing data in correct order
  console.log('🧹 Cleaning database...')
  await prisma.walletTransaction.deleteMany()
  await prisma.shipping.deleteMany()
  await prisma.order.deleteMany()
  await prisma.bid.deleteMany()
  await prisma.watchlist.deleteMany()
  await prisma.notification.deleteMany()
  await prisma.productComment.deleteMany()
  await prisma.message.deleteMany()
  await prisma.chatRoom.deleteMany()
  await prisma.auctionProduct.deleteMany()
  await prisma.auction.deleteMany()
  await prisma.productImage.deleteMany()
  await prisma.productCategory.deleteMany()
  await prisma.product.deleteMany()
  await prisma.category.deleteMany()
  await prisma.follow.deleteMany()
  await prisma.address.deleteMany()
  await prisma.profile.deleteMany()
  await prisma.warning.deleteMany()
  await prisma.user.deleteMany()

  // Hash password
  const hashedPassword = await bcrypt.hash('123456', 10)

  // Create categories
  console.log('📁 Creating categories...')
  const categories = await Promise.all([
    prisma.category.create({ data: { name: CategoryType.ELECTRONICS } }),
    prisma.category.create({ data: { name: CategoryType.FASHION } }),
    prisma.category.create({ data: { name: CategoryType.COLLECTIBLES } }),
    prisma.category.create({ data: { name: CategoryType.HOME_APPLIANCES } }),
    prisma.category.create({ data: { name: CategoryType.SPORTS_EQUIPMENT } }),
    prisma.category.create({ data: { name: CategoryType.TOYS_AND_GAMES } }),
    prisma.category.create({ data: { name: CategoryType.VEHICLES } }),
    prisma.category.create({ data: { name: CategoryType.ART_AND_CRAFTS } }),
    prisma.category.create({ data: { name: CategoryType.JEWELRY_AND_ACCESSORIES } }),
    prisma.category.create({ data: { name: CategoryType.HEALTH_AND_BEAUTY } }),
  ])

  // Create 1 admin
  console.log('👑 Creating admin...')
  const admin = await prisma.user.create({
    data: {
      email: 'admin@auction.com',
      password: hashedPassword,
      role: Role.ADMIN,
      isVerified: true,
      walletBalance: new Decimal(0),
    },
  })

  await prisma.profile.create({
    data: {
      userId: admin.userId,
      fullName: 'Admin User',
      phoneNumber: '+84901234567',
      profileImageUrl: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=400&h=400&fit=crop&crop=face',
    },
  })

  // Create 5 bidders
  console.log('🤝 Creating bidders...')
  const bidders = []
  const bidderNames = ['Alice Johnson', 'Bob Smith', 'Charlie Brown', 'Diana Ross', 'Edward Norton']
  const bidderEmails = ['alice@gmail.com', 'bob@gmail.com', 'charlie@gmail.com', 'diana@gmail.com', 'edward@gmail.com']

  for (let i = 0; i < 5; i++) {
    const bidder = await prisma.user.create({
      data: {
        email: bidderEmails[i],
        password: hashedPassword,
        role: Role.BIDDER,
        isVerified: true,
        walletBalance: new Decimal(Math.floor(Math.random() * 50000) + 10000), // 10,000 - 60,000
      },
    })

    await prisma.profile.create({
      data: {
        userId: bidder.userId,
        fullName: bidderNames[i],
        phoneNumber: `+8490123456${i}`,
        profileImageUrl: `https://images.unsplash.com/photo-15${40 + i}0${10 + i}0000-0000-000000000000?w=400&h=400&fit=crop&crop=face`,
      },
    })

    await prisma.address.create({
      data: {
        userId: bidder.userId,
        streetAddress: `${100 + i * 10} Main Street`,
        city: ['Ho Chi Minh City', 'Hanoi', 'Da Nang', 'Can Tho', 'Hai Phong'][i],
        state: 'Vietnam',
        postalCode: `70000${i}`,
        country: 'Vietnam',
        addressType: AddressType.Home,
      },
    })

    bidders.push(bidder)
  }

  // Create 5 sellers
  console.log('🏪 Creating sellers...')
  const sellers = []
  const sellerNames = ['Fashion Store', 'Tech Hub', 'Antique Collector', 'Sports World', 'Gadget Central']
  const sellerEmails = ['fashion@store.com', 'tech@hub.com', 'antique@collector.com', 'sports@world.com', 'gadget@central.com']

  for (let i = 0; i < 5; i++) {
    const seller = await prisma.user.create({
      data: {
        email: sellerEmails[i],
        password: hashedPassword,
        role: Role.SELLER,
        isVerified: true,
        walletBalance: new Decimal(Math.floor(Math.random() * 100000) + 20000), // 20,000 - 120,000
      },
    })

    await prisma.profile.create({
      data: {
        userId: seller.userId,
        fullName: sellerNames[i],
        phoneNumber: `+8490765432${i}`,
        profileImageUrl: `https://images.unsplash.com/photo-156${i}00000000-0000-0000-0000-000000000000?w=400&h=400&fit=crop&crop=face`,
      },
    })

    await prisma.address.create({
      data: {
        userId: seller.userId,
        streetAddress: `${200 + i * 20} Business District`,
        city: ['Ho Chi Minh City', 'Hanoi', 'Da Nang', 'Can Tho', 'Hai Phong'][i],
        state: 'Vietnam',
        postalCode: `80000${i}`,
        country: 'Vietnam',
        addressType: AddressType.Work,
      },
    })

    sellers.push(seller)
  }

  // Create follows (bidders follow sellers)
  console.log('👥 Creating follow relationships...')
  for (const bidder of bidders) {
    // Each bidder follows 2-3 random sellers
    const followCount = Math.floor(Math.random() * 2) + 2
    const shuffledSellers = [...sellers].sort(() => 0.5 - Math.random())
    
    for (let i = 0; i < followCount; i++) {
      await prisma.follow.create({
        data: {
          followerId: bidder.userId,
          sellerId: shuffledSellers[i].userId,
        },
      })
    }
  }

  // Create 50 products
  console.log('📦 Creating products...')
  const products = []
  const productData = [
    // Electronics
    { name: 'iPhone 15 Pro Max', description: 'Latest Apple smartphone with titanium design and A17 Pro chip', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1592750475338-74b7b21085ab?w=800&h=600&fit=crop'] },
    { name: 'MacBook Pro M3', description: 'Professional laptop with M3 chip for ultimate performance', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=800&h=600&fit=crop'] },
    { name: 'Samsung Galaxy S24 Ultra', description: 'Flagship Android phone with S Pen and AI features', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=800&h=600&fit=crop'] },
    { name: 'iPad Pro 12.9"', description: 'Professional tablet for creative work and productivity', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?w=800&h=600&fit=crop'] },
    { name: 'Sony WH-1000XM5', description: 'Premium noise-canceling headphones', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1618366712010-f4ae9c647dcb?w=800&h=600&fit=crop'] },
    
    // Fashion
    { name: 'Luxury Swiss Watch', description: 'Vintage mechanical watch from renowned Swiss manufacturer', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=800&h=600&fit=crop'] },
    { name: 'Designer Leather Handbag', description: 'Authentic designer handbag in pristine condition', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=800&h=600&fit=crop'] },
    { name: 'Vintage Denim Jacket', description: 'Rare vintage denim jacket from the 1980s', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=800&h=600&fit=crop'] },
    { name: 'Silk Scarf Collection', description: 'Set of 5 premium silk scarves from luxury brand', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1584464491033-06628f3a6b7b?w=800&h=600&fit=crop'] },
    { name: 'Limited Edition Sneakers', description: 'Rare limited edition sneakers, never worn', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1549298916-b41d501d3772?w=800&h=600&fit=crop'] },

    // Collectibles
    { name: 'Vintage Vinyl Records', description: 'Collection of rare vinyl records from the 1960s-1970s', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=800&h=600&fit=crop'] },
    { name: 'Antique Pocket Watch', description: 'Gold-plated pocket watch from early 1900s', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1509048191080-d2e72ad8b5df?w=800&h=600&fit=crop'] },
    { name: 'Rare Comic Book', description: 'First edition comic book in mint condition', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1601645191163-3fc0d5d64e35?w=800&h=600&fit=crop'] },
    { name: 'Vintage Camera', description: 'Classic film camera from renowned manufacturer', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=800&h=600&fit=crop'] },
    { name: 'Antique Vase', description: 'Beautiful ceramic vase from Ming dynasty period', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=800&h=600&fit=crop'] },

    // Home Appliances
    { name: 'Smart Refrigerator', description: 'Energy-efficient smart refrigerator with WiFi connectivity', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1571175443880-49e1d25b2bc5?w=800&h=600&fit=crop'] },
    { name: 'Robot Vacuum Cleaner', description: 'Advanced robot vacuum with mapping technology', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800&h=600&fit=crop'] },
    { name: 'Air Purifier', description: 'HEPA air purifier for large rooms', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1585771724684-38269d6639fd?w=800&h=600&fit=crop'] },
    { name: 'Smart Thermostat', description: 'Programmable smart thermostat with app control', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1545259741-2ea3ebf61fa9?w=800&h=600&fit=crop'] },
    { name: 'Espresso Machine', description: 'Professional-grade espresso machine for home use', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=800&h=600&fit=crop'] },

    // Sports Equipment
    { name: 'Professional Tennis Racket', description: 'Used by professional players, excellent condition', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=800&h=600&fit=crop'] },
    { name: 'Mountain Bike', description: 'High-end mountain bike for extreme trails', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1544191696-15693072f5aa?w=800&h=600&fit=crop'] },
    { name: 'Golf Club Set', description: 'Complete professional golf club set with bag', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1535131749006-b7f58c99034b?w=800&h=600&fit=crop'] },
    { name: 'Yoga Mat Set', description: 'Premium yoga mat with accessories', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1506629905607-eeb18d7b7502?w=800&h=600&fit=crop'] },
    { name: 'Basketball Shoes', description: 'Professional basketball shoes, limited edition', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=800&h=600&fit=crop'] },

    // Additional items to reach 50
    { name: 'Gaming Laptop', description: 'High-performance gaming laptop with RTX graphics', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1603302576837-37561b2e2302?w=800&h=600&fit=crop'] },
    { name: 'Wireless Earbuds', description: 'Premium true wireless earbuds with ANC', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1572569511254-d8f925fe2cbb?w=800&h=600&fit=crop'] },
    { name: 'Smart Watch', description: 'Fitness tracking smartwatch with GPS', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=800&h=600&fit=crop'] },
    { name: 'Mechanical Keyboard', description: 'RGB mechanical keyboard for gaming', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1541140532154-b024d705b90a?w=800&h=600&fit=crop'] },
    { name: 'Portable Monitor', description: 'USB-C portable monitor for productivity', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?w=800&h=600&fit=crop'] },
    { name: 'Designer Sunglasses', description: 'Luxury designer sunglasses with UV protection', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1511499767150-a48a237f0083?w=800&h=600&fit=crop'] },
    { name: 'Leather Wallet', description: 'Handcrafted leather wallet with RFID protection', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=800&h=600&fit=crop'] },
    { name: 'Vintage Jacket', description: 'Authentic vintage leather jacket from 1970s', category: CategoryType.FASHION, images: ['https://images.unsplash.com/photo-1551488831-00ddcb6c6bd3?w=800&h=600&fit=crop'] },
    { name: 'Pearl Necklace', description: 'Genuine pearl necklace with gold clasp', category: CategoryType.JEWELRY_AND_ACCESSORIES, images: ['https://images.unsplash.com/photo-1515562141207-7a88fb7ce338?w=800&h=600&fit=crop'] },
    { name: 'Diamond Ring', description: 'Certified diamond engagement ring', category: CategoryType.JEWELRY_AND_ACCESSORIES, images: ['https://images.unsplash.com/photo-1605100804763-247f67b3557e?w=800&h=600&fit=crop'] },
    { name: 'Antique Clock', description: 'Working antique grandfather clock', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1563861826100-9cb868fdbe1c?w=800&h=600&fit=crop'] },
    { name: 'Vintage Guitar', description: 'Classic acoustic guitar from 1960s', category: CategoryType.COLLECTIBLES, images: ['https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=800&h=600&fit=crop'] },
    { name: 'Art Painting', description: 'Original oil painting by local artist', category: CategoryType.ART_AND_CRAFTS, images: ['https://images.unsplash.com/photo-1541961017774-22349e4a1262?w=800&h=600&fit=crop'] },
    { name: 'Handmade Pottery', description: 'Set of handmade ceramic pottery', category: CategoryType.ART_AND_CRAFTS, images: ['https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=800&h=600&fit=crop'] },
    { name: 'Gaming Chair', description: 'Ergonomic gaming chair with RGB lighting', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1586953208448-b95a79798f07?w=800&h=600&fit=crop'] },
    { name: 'Standing Desk', description: 'Adjustable height standing desk', category: CategoryType.HOME_APPLIANCES, images: ['https://images.unsplash.com/photo-1586953135030-d0b1c2b9a4d7?w=800&h=600&fit=crop'] },
    { name: 'Electric Scooter', description: 'Foldable electric scooter for commuting', category: CategoryType.VEHICLES, images: ['https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800&h=600&fit=crop'] },
    { name: 'Drone Camera', description: '4K drone with gimbal stabilization', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1473968512647-3e447244af8f?w=800&h=600&fit=crop'] },
    { name: 'Board Game Collection', description: 'Rare board games collection', category: CategoryType.TOYS_AND_GAMES, images: ['https://images.unsplash.com/photo-1606092195730-5d7b9af1efc5?w=800&h=600&fit=crop'] },
    { name: 'Action Figure Set', description: 'Limited edition action figures in original packaging', category: CategoryType.TOYS_AND_GAMES, images: ['https://images.unsplash.com/photo-1601645191163-3fc0d5d64e35?w=800&h=600&fit=crop'] },
    { name: 'Skincare Set', description: 'Premium skincare routine set', category: CategoryType.HEALTH_AND_BEAUTY, images: ['https://images.unsplash.com/photo-1556228720-195a672e8a03?w=800&h=600&fit=crop'] },
    { name: 'Hair Styling Tools', description: 'Professional hair styling tool kit', category: CategoryType.HEALTH_AND_BEAUTY, images: ['https://images.unsplash.com/photo-1522338140262-f46f5913618a?w=800&h=600&fit=crop'] },
    { name: 'Garden Tool Set', description: 'Complete gardening tool set with storage', category: CategoryType.GARDEN_AND_OUTDOORS, images: ['https://images.unsplash.com/photo-1416879595882-3373a0480b5b?w=800&h=600&fit=crop'] },
    { name: 'Outdoor Furniture', description: 'Weather-resistant patio furniture set', category: CategoryType.GARDEN_AND_OUTDOORS, images: ['https://images.unsplash.com/photo-1506439773649-6e0eb8cfb237?w=800&h=600&fit=crop'] },
    { name: 'Pet Supplies Kit', description: 'Complete pet care supplies for dogs', category: CategoryType.PET_SUPPLIES, images: ['https://images.unsplash.com/photo-1601758228041-f3b2795255f1?w=800&h=600&fit=crop'] },
    { name: 'Office Supplies Bundle', description: 'Premium office supplies for professionals', category: CategoryType.OFFICE_SUPPLIES, images: ['https://images.unsplash.com/photo-1541140532154-b024d705b90a?w=800&h=600&fit=crop'] },
    { name: 'Musical Keyboard', description: 'Digital piano keyboard with weighted keys', category: CategoryType.MUSIC_INSTRUMENTS, images: ['https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=800&h=600&fit=crop'] },
    { name: 'DJ Equipment', description: 'Professional DJ controller and mixer', category: CategoryType.MUSIC_INSTRUMENTS, images: ['https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=800&h=600&fit=crop'] },
    { name: 'Fitness Equipment', description: 'Home gym equipment set', category: CategoryType.SPORTS_EQUIPMENT, images: ['https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=800&h=600&fit=crop'] },
    { name: 'Camping Gear', description: 'Complete camping gear for outdoor adventures', category: CategoryType.GARDEN_AND_OUTDOORS, images: ['https://images.unsplash.com/photo-1504280390367-361c6d9f38f4?w=800&h=600&fit=crop'] },
    { name: 'Photography Equipment', description: 'Professional camera lens and accessories', category: CategoryType.ELECTRONICS, images: ['https://images.unsplash.com/photo-1526170375885-4d8ecf77b99f?w=800&h=600&fit=crop'] },
  ]

  for (let i = 0; i < 50; i++) {
    const item = productData[i]
    const seller = sellers[i % sellers.length]
    const categoryMatch = categories.find(cat => cat.name === item.category)

    const product = await prisma.product.create({
      data: {
        name: item.name,
        description: item.description,
        sellerId: seller.userId,
        status: ProductStatus.ACTIVE,
        stockQuantity: Math.floor(Math.random() * 10) + 1,
      },
    })

    // Add product to category
    if (categoryMatch) {
      await prisma.productCategory.create({
        data: {
          productId: product.productId,
          categoryId: categoryMatch.categoryId,
        },
      })
    }

    // Add product images
    for (const imageUrl of item.images) {
      await prisma.productImage.create({
        data: {
          productId: product.productId,
          imageUrl,
          isPrimary: true,
        },
      })
    }

    products.push(product)
  }

  // Create auctions for products
  console.log('🏛️ Creating auctions...')
  const auctions = []
  
  for (let i = 0; i < products.length; i++) {
    const product = products[i]
    const seller = sellers.find(s => s.userId === product.sellerId)
    
    const startTime = new Date()
    startTime.setHours(startTime.getHours() - Math.floor(Math.random() * 48)) // Started 0-48 hours ago
    
    const endTime = new Date(startTime)
    endTime.setHours(endTime.getHours() + Math.floor(Math.random() * 72) + 24) // Runs for 24-96 hours
    
    const startingPrice = Math.floor(Math.random() * 1000) + 100
    const currentPrice = startingPrice + Math.floor(Math.random() * 500)
    
    const statuses = [AuctionStatus.OPEN, AuctionStatus.CLOSED, AuctionStatus.COMPLETED]
    const status = statuses[Math.floor(Math.random() * statuses.length)]
    
    const auction = await prisma.auction.create({
      data: {
        title: `Auction for ${product.name}`,
        sellerId: seller!.userId,
        startTime,
        endTime,
        currentPrice: new Decimal(currentPrice),
        startingPrice: new Decimal(startingPrice),
        status,
        minimumBidIncrement: new Decimal(10),
        lastBidTime: new Date(),
        bidCount: Math.floor(Math.random() * 20),
      },
    })

    // Link auction to product
    await prisma.auctionProduct.create({
      data: {
        auctionId: auction.auctionId,
        productId: product.productId,
        quantity: 1,
      },
    })

    auctions.push(auction)
  }

  // Create bids for auctions
  console.log('💰 Creating bids...')
  const allBids = []
  
  for (const auction of auctions) {
    if (auction.status === AuctionStatus.OPEN || auction.status === AuctionStatus.CLOSED || auction.status === AuctionStatus.COMPLETED) {
      const bidCount = Math.floor(Math.random() * 10) + 1
      
      for (let i = 0; i < bidCount; i++) {
        const bidder = bidders[Math.floor(Math.random() * bidders.length)]
        const bidAmount = new Decimal(auction.startingPrice.toNumber() + (i + 1) * auction.minimumBidIncrement.toNumber() + Math.floor(Math.random() * 50))
        
        const bid = await prisma.bid.create({
          data: {
            auctionId: auction.auctionId,
            userId: bidder.userId,
            bidAmount,
            status: BidStatus.VALID,
          },
        })

        // Create wallet transaction for bid
        await prisma.walletTransaction.create({
          data: {
            userId: bidder.userId,
            type: TransactionType.BID_PAYMENT,
            status: TransactionStatus.SUCCESS,
            amount: bidAmount,
            balanceAfter: new Decimal(bidder.walletBalance.toNumber() - bidAmount.toNumber()),
            auctionId: auction.auctionId,
            bidId: bid.bidId,
            description: `Bid placed on auction: ${auction.title}`,
          },
        })

        allBids.push(bid)
      }
    }
  }

  // Update auction winners for completed auctions
  console.log('🏆 Setting auction winners...')
  for (const auction of auctions) {
    if (auction.status === AuctionStatus.COMPLETED || auction.status === AuctionStatus.CLOSED) {
      // Get highest bid for this auction
      const highestBid = await prisma.bid.findFirst({
        where: { auctionId: auction.auctionId },
        orderBy: { bidAmount: 'desc' },
      })

      if (highestBid) {
        await prisma.auction.update({
          where: { auctionId: auction.auctionId },
          data: {
            winnerId: highestBid.userId,
            currentPrice: highestBid.bidAmount,
          },
        })
      }
    }
  }

  // Create 70 orders with proper status relationships
  console.log('📋 Creating orders...')
  const orders = []
  const orderStatuses = [OrderStatus.PENDING, OrderStatus.PAID, OrderStatus.SHIPPING, OrderStatus.COMPLETED, OrderStatus.CANCELED]
  
  for (let i = 0; i < 70; i++) {
    const auction = auctions[i % auctions.length]
    const buyer = bidders[i % bidders.length]
    const status = orderStatuses[Math.floor(Math.random() * orderStatuses.length)]
    
    const order = await prisma.order.create({
      data: {
        userId: buyer.userId,
        auctionId: auction.auctionId,
        totalAmount: new Decimal(auction.currentPrice.toNumber() + Math.floor(Math.random() * 100)), // Add shipping cost
        status,
        paymentDueDate: status === OrderStatus.PENDING ? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) : null, // 7 days from now
      },
    })

    orders.push(order)
  }

  // Create shipping records based on order status
  console.log('🚚 Creating shipping records...')
  for (const order of orders) {
    let shippingStatus: ShippingStatus | null = null
    
    // Map order status to shipping status according to requirements
    switch (order.status) {
      case OrderStatus.PENDING:
        // No shipping record for pending orders
        continue
      case OrderStatus.PAID:
        shippingStatus = ShippingStatus.PENDING
        break
      case OrderStatus.SHIPPING:
        shippingStatus = Math.random() > 0.5 ? ShippingStatus.SHIPPED : ShippingStatus.IN_TRANSIT
        break
      case OrderStatus.COMPLETED:
        shippingStatus = ShippingStatus.DELIVERED
        break
      case OrderStatus.CANCELED:
        // Shipping is invalid for canceled orders - skip
        continue
    }

    const auction = auctions.find(a => a.auctionId === order.auctionId)
    if (!auction) continue

    const seller = sellers.find(s => s.userId === auction.sellerId)
    if (!seller) continue

    const shipping = await prisma.shipping.create({
      data: {
        orderId: order.orderId,
        auctionId: order.auctionId,
        sellerId: seller.userId,
        buyerId: order.userId,
        shippingStatus,
        price: new Decimal(Math.floor(Math.random() * 50) + 20), // Shipping cost between 20-70
        trackingNumber: shippingStatus !== ShippingStatus.PENDING ? `VN${Date.now()}${Math.floor(Math.random() * 1000)}` : null,
        shippedAt: shippingStatus === ShippingStatus.SHIPPED || shippingStatus === ShippingStatus.IN_TRANSIT || shippingStatus === ShippingStatus.DELIVERED 
          ? new Date(Date.now() - Math.floor(Math.random() * 5) * 24 * 60 * 60 * 1000) : null, // Shipped 0-5 days ago
        estimatedDelivery: shippingStatus !== ShippingStatus.PENDING 
          ? new Date(Date.now() + Math.floor(Math.random() * 7) * 24 * 60 * 60 * 1000) : null, // Delivery in 0-7 days
        actualDelivery: shippingStatus === ShippingStatus.DELIVERED 
          ? new Date(Date.now() - Math.floor(Math.random() * 3) * 24 * 60 * 60 * 1000) : null, // Delivered 0-3 days ago
      },
    })
  }

  // Create some notifications
  console.log('🔔 Creating notifications...')
  for (const bidder of bidders) {
    for (let i = 0; i < 3; i++) {
      await prisma.notification.create({
        data: {
          userId: bidder.userId,
          message: [
            'Your bid has been outbid on iPhone 15 Pro Max auction',
            'New auction started: MacBook Pro M3 - Don\'t miss out!',
            'Auction ending soon: Samsung Galaxy S24 Ultra',
            'You won the auction for Vintage Swiss Watch!',
            'Payment reminder: Please complete payment for your won auction',
          ][Math.floor(Math.random() * 5)],
          isRead: Math.random() > 0.5,
          metadata: {
            type: 'auction',
            auctionId: auctions[Math.floor(Math.random() * auctions.length)].auctionId,
          },
        },
      })
    }
  }

  // Create some product comments
  console.log('💬 Creating product comments...')
  for (let i = 0; i < 20; i++) {
    const product = products[i % products.length]
    const commenter = bidders[i % bidders.length]
    
    await prisma.productComment.create({
      data: {
        productId: product.productId,
        userId: commenter.userId,
        content: [
          'Great product! Exactly as described.',
          'Fast shipping and excellent condition.',
          'Would definitely buy from this seller again.',
          'Product quality exceeded my expectations.',
          'Highly recommended!',
        ][Math.floor(Math.random() * 5)],
        rating: Math.floor(Math.random() * 2) + 4, // 4-5 stars
      },
    })
  }

  // Create some watchlist entries
  console.log('👁️ Creating watchlist entries...')
  for (const bidder of bidders) {
    // Each bidder watches 3-5 random auctions
    const watchCount = Math.floor(Math.random() * 3) + 3
    const shuffledAuctions = [...auctions].sort(() => 0.5 - Math.random())
    
    for (let i = 0; i < watchCount; i++) {
      await prisma.watchlist.create({
        data: {
          userId: bidder.userId,
          auctionId: shuffledAuctions[i].auctionId,
        },
      })
    }
  }

  console.log('✅ Seed completed successfully!')
  console.log(`Created:
  - 1 admin
  - 5 bidders  
  - 5 sellers
  - 50 products
  - 50 auctions
  - 70 orders
  - Shipping records (only for valid order statuses)
  - ${allBids.length} bids
  - Follow relationships
  - Product comments
  - Notifications
  - Watchlist entries`)
}

main()
  .catch((e) => {
    console.error('Error during seed:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
