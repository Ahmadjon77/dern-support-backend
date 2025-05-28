// // ===== SIMPLE ADMIN PANEL - Muammosiz versiya =====

// console.log("🔧 Simple Admin Panel yuklandi")

// // Global variables
// let currentUser = null
// let allOrders = []
// let allUsers = []
// const API = {} // Declare API variable

// // Initialize admin panel
// document.addEventListener("DOMContentLoaded", async () => {
//   console.log("📱 Admin panel ishga tushmoqda...")

//   try {
//     // Check authentication
//     await checkAuthentication()

//     // Load admin data
//     await loadAdminData()

//     // Setup UI
//     setupAdminUI()

//     console.log("✅ Admin panel muvaffaqiyatli yuklandi")
//   } catch (error) {
//     console.error("❌ Admin panel yuklashda xato:", error)
//     handleAuthError()
//   }
// })

// // Check authentication
// async function checkAuthentication() {
//   console.log("🔐 Authentication tekshirilmoqda...")

//   // Try to get user from localStorage first
//   const storedUser = localStorage.getItem("currentUser")
//   const authToken = localStorage.getItem("authToken")

//   if (!storedUser || !authToken) {
//     throw new Error("User yoki token topilmadi")
//   }

//   try {
//     currentUser = JSON.parse(storedUser)
//     console.log("👤 Current user:", currentUser)

//     // Check if user is admin
//     if (currentUser.role !== "admin") {
//       throw new Error("Admin huquqi yo'q")
//     }

//     console.log("✅ Admin authentication muvaffaqiyatli")
//   } catch (parseError) {
//     console.error("❌ User ma'lumotlarini parse qilishda xato:", parseError)
//     throw parseError
//   }
// }

// // Load admin data
// async function loadAdminData() {
//   console.log("📊 Admin ma'lumotlari yuklanmoqda...")

//   try {
//     // Try API first
//     if (typeof API !== "undefined" && API.TokenManager.getToken()) {
//       console.log("🌐 API orqali ma'lumot yuklash...")

//       try {
//         const stats = await API.Admin.getDashboardStats()
//         allOrders = await API.Orders.getUserOrders()

//         updateStatsUI(stats)
//         console.log("✅ API ma'lumotlari yuklandi")
//         return
//       } catch (apiError) {
//         console.log("⚠️ API xatosi, localStorage ishlatiladi:", apiError.message)
//       }
//     }

//     // Fallback to localStorage
//     console.log("💾 localStorage dan ma'lumot yuklash...")
//     loadLocalStorageData()
//   } catch (error) {
//     console.error("❌ Ma'lumot yuklashda xato:", error)
//     loadLocalStorageData() // Always fallback to localStorage
//   }
// }

// // Load data from localStorage
// function loadLocalStorageData() {
//   // Load orders
//   allOrders = JSON.parse(localStorage.getItem("userOrders") || "[]")

//   // Load users
//   allUsers = JSON.parse(localStorage.getItem("registeredUsers") || "[]")

//   // Calculate stats
//   const stats = {
//     totalOrders: allOrders.length,
//     totalUsers: allUsers.length,
//     totalProducts: 0,
//     totalRevenue: allOrders.filter((o) => o.status === "completed").length * 150000,
//     pendingOrders: allOrders.filter((o) => o.status === "pending").length,
//     completedOrders: allOrders.filter((o) => o.status === "completed").length,
//   }

//   updateStatsUI(stats)
//   console.log("✅ LocalStorage ma'lumotlari yuklandi")
// }

// // Update stats UI
// function updateStatsUI(stats) {
//   console.log("📊 Stats UI yangilanmoqda:", stats)

//   // Update admin name
//   const adminNameEl = document.getElementById("adminName")
//   if (adminNameEl && currentUser) {
//     adminNameEl.textContent = currentUser.firstName + " " + currentUser.lastName
//   }

//   // Update stats
//   const statsElements = {
//     totalOrdersCount: stats.totalOrders,
//     totalUsersCount: stats.totalUsers,
//     totalProductsCount: stats.totalProducts,
//     totalRevenue: formatCurrency(stats.totalRevenue || 0),
//   }

//   Object.entries(statsElements).forEach(([id, value]) => {
//     const element = document.getElementById(id)
//     if (element) {
//       element.textContent = value
//     }
//   })

//   console.log("✅ Stats UI yangilandi")
// }

// // Setup admin UI
// function setupAdminUI() {
//   console.log("🎨 Admin UI sozlanmoqda...")

//   // Load initial tab (orders)
//   showAdminTab("orders")

//   // Setup auto refresh
//   setInterval(() => {
//     console.log("🔄 Auto refresh...")
//     loadAdminData()
//   }, 30000) // 30 seconds

//   console.log("✅ Admin UI sozlandi")
// }

// // Show admin tab
// function showAdminTab(tabName) {
//   console.log("📑 Tab ko'rsatilmoqda:", tabName)

//   // Remove active class from all tabs
//   document.querySelectorAll(".tab-btn").forEach((btn) => {
//     btn.classList.remove("active")
//   })
//   document.querySelectorAll(".tab-content").forEach((content) => {
//     content.classList.remove("active")
//   })

//   // Add active class to selected tab
//   const activeBtn = document.querySelector(`[onclick="showAdminTab('${tabName}')"]`)
//   if (activeBtn) {
//     activeBtn.classList.add("active")
//   }

//   const tabContent = document.getElementById(tabName + "-admin-tab")
//   if (tabContent) {
//     tabContent.classList.add("active")
//   }

//   // Load tab content
//   switch (tabName) {
//     case "orders":
//       loadOrdersTab()
//       break
//     case "users":
//       loadUsersTab()
//       break
//     case "products":
//       loadProductsTab()
//       break
//     case "settings":
//       loadSettingsTab()
//       break
//   }
// }

// // Load orders tab
// function loadOrdersTab() {
//   console.log("📦 Orders tab yuklanmoqda...")

//   const container = document.getElementById("admin-orders-list")
//   if (!container) {
//     console.log("❌ Orders container topilmadi")
//     return
//   }

//   if (allOrders.length === 0) {
//     container.innerHTML = `
//             <div class="empty-state">
//                 <i class="fas fa-shopping-cart"></i>
//                 <h3>Buyurtmalar yo'q</h3>
//                 <p>Hozircha tizimda buyurtmalar yo'q.</p>
//             </div>
//         `
//     return
//   }

//   const ordersHTML = allOrders
//     .map(
//       (order) => `
//         <div class="admin-order-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px;">
//             <div class="order-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
//                 <div class="order-info">
//                     <strong>Buyurtma #${order.id}</strong>
//                     <span style="margin-left: 10px; color: #666;">${order.firstName} ${order.lastName}</span>
//                     <span style="margin-left: 10px; color: #666;">${formatDate(order.createdAt)}</span>
//                 </div>
//                 <div class="order-status">
//                     <select onchange="updateOrderStatus('${order.id}', this.value)" style="padding: 5px;">
//                         <option value="pending" ${order.status === "pending" ? "selected" : ""}>Kutilmoqda</option>
//                         <option value="in-progress" ${order.status === "in-progress" ? "selected" : ""}>Jarayonda</option>
//                         <option value="completed" ${order.status === "completed" ? "selected" : ""}>Tugallangan</option>
//                         <option value="cancelled" ${order.status === "cancelled" ? "selected" : ""}>Bekor qilingan</option>
//                     </select>
//                 </div>
//             </div>
//             <div class="order-details">
//                 <p><strong>Xizmat:</strong> ${getServiceName(order.serviceType)}</p>
//                 <p><strong>Muammo:</strong> ${order.problem}</p>
//                 <p><strong>Telefon:</strong> ${order.phone}</p>
//                 <p><strong>Email:</strong> ${order.email}</p>
//                 ${order.address ? `<p><strong>Manzil:</strong> ${order.address}</p>` : ""}
//             </div>
//         </div>
//     `,
//     )
//     .join("")

//   container.innerHTML = ordersHTML
//   console.log("✅ Orders tab yuklandi")
// }

// // Load users tab
// function loadUsersTab() {
//   console.log("👥 Users tab yuklanmoqda...")

//   const container = document.getElementById("admin-users-list")
//   if (!container) {
//     console.log("❌ Users container topilmadi")
//     return
//   }

//   if (allUsers.length === 0) {
//     container.innerHTML = `
//             <div class="empty-state">
//                 <i class="fas fa-users"></i>
//                 <h3>Foydalanuvchilar yo'q</h3>
//                 <p>Hozircha ro'yxatdan o'tgan foydalanuvchilar yo'q.</p>
//             </div>
//         `
//     return
//   }

//   const usersHTML = allUsers
//     .map(
//       (user) => `
//         <div class="admin-user-item" style="border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px;">
//             <div style="display: flex; justify-content: space-between; align-items: center;">
//                 <div>
//                     <h4>${user.firstName} ${user.lastName}</h4>
//                     <p>Email: ${user.email}</p>
//                     <p>Telefon: ${user.phone || "Kiritilmagan"}</p>
//                     <p>Rol: <span style="background: ${user.role === "admin" ? "#28a745" : "#007bff"}; color: white; padding: 2px 8px; border-radius: 3px;">${user.role}</span></p>
//                 </div>
//                 <div>
//                     <small>Ro'yxatdan o'tgan: ${formatDate(user.createdAt)}</small>
//                 </div>
//             </div>
//         </div>
//     `,
//     )
//     .join("")

//   container.innerHTML = usersHTML
//   console.log("✅ Users tab yuklandi")
// }

// // Load products tab
// function loadProductsTab() {
//   const container = document.getElementById("admin-products-list")
//   if (container) {
//     container.innerHTML = `
//             <div class="empty-state">
//                 <i class="fas fa-box"></i>
//                 <h3>Mahsulotlar bo'limi</h3>
//                 <p>Bu bo'lim hozircha ishlab chiqilmoqda.</p>
//             </div>
//         `
//   }
// }

// // Load settings tab
// function loadSettingsTab() {
//   console.log("⚙️ Settings tab yuklandi")
// }

// // Update order status
// function updateOrderStatus(orderId, newStatus) {
//   console.log("📝 Order status yangilanmoqda:", orderId, newStatus)

//   // Find and update order
//   const orderIndex = allOrders.findIndex((order) => order.id === orderId)
//   if (orderIndex !== -1) {
//     allOrders[orderIndex].status = newStatus
//     allOrders[orderIndex].updatedAt = new Date().toISOString()

//     // Save to localStorage
//     localStorage.setItem("userOrders", JSON.stringify(allOrders))

//     // Show success message
//     showMessage("Buyurtma statusi yangilandi!", "success")

//     // Refresh stats
//     loadAdminData()

//     console.log("✅ Order status yangilandi")
//   } else {
//     console.log("❌ Order topilmadi:", orderId)
//     showMessage("Buyurtma topilmadi!", "error")
//   }
// }

// // Handle authentication error
// function handleAuthError() {
//   console.log("🚨 Authentication xatosi")

//   // Show error message
//   document.body.innerHTML = `
//         <div style="display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column;">
//             <div style="text-align: center; padding: 40px; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
//                 <i class="fas fa-exclamation-triangle" style="font-size: 48px; color: #f39c12; margin-bottom: 20px;"></i>
//                 <h2>Admin panelga kirish xatosi</h2>
//                 <p>Admin huquqi talab qilinadi yoki authentication muammosi.</p>
//                 <div style="margin-top: 20px;">
//                     <a href="admin-debug.html" class="btn btn-primary" style="margin-right: 10px;">Debug sahifasi</a>
//                     <a href="login.html" class="btn btn-outline">Login sahifasi</a>
//                 </div>
//             </div>
//         </div>
//     `
// }

// // Helper functions
// function getServiceName(serviceType) {
//   const services = {
//     repair: "Kompyuter ta'mirlash",
//     software: "Dasturiy ta'minot",
//     consultation: "IT maslahat",
//     maintenance: "Texnik xizmat",
//   }
//   return services[serviceType] || serviceType
// }

// function formatDate(dateString) {
//   return new Date(dateString).toLocaleDateString("uz-UZ")
// }

// function formatCurrency(amount) {
//   return amount.toLocaleString() + " so'm"
// }

// function showMessage(message, type) {
//   console.log(`📢 Message (${type}):`, message)

//   // Create message element
//   const messageEl = document.createElement("div")
//   messageEl.style.cssText = `
//         position: fixed;
//         top: 20px;
//         right: 20px;
//         padding: 15px 20px;
//         border-radius: 5px;
//         color: white;
//         font-weight: bold;
//         z-index: 1000;
//         ${type === "success" ? "background: #28a745;" : ""}
//         ${type === "error" ? "background: #dc3545;" : ""}
//         ${type === "info" ? "background: #17a2b8;" : ""}
//     `
//   messageEl.textContent = message

//   document.body.appendChild(messageEl)

//   // Remove after 3 seconds
//   setTimeout(() => {
//     messageEl.remove()
//   }, 3000)
// }

// // Logout function
// function logout() {
//   if (confirm("Admin paneldan chiqishni xohlaysizmi?")) {
//     localStorage.removeItem("currentUser")
//     localStorage.removeItem("authToken")
//     window.location.href = "login.html"
//   }
// }

// // Make functions globally available
// window.showAdminTab = showAdminTab
// window.updateOrderStatus = updateOrderStatus
// window.logout = logout

// console.log("✅ Simple Admin Panel to'liq yuklandi")
