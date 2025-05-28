document.addEventListener("DOMContentLoaded", async () => {
    console.log("dashboard.js loaded, API:", window.API);

    // Foydalanuvchi ma'lumotlarini tekshirish
    const user = checkAuth();
    if (!user) return;

    // Foydalanuvchi ismini ko'rsatish
    const userNameElements = document.querySelectorAll("#userName, #user-name");
    userNameElements.forEach((element) => {
        element.textContent = user.firstName || "Foydalanuvchi";
    });

    // Buyurtmalarni yuklash
    await loadOrders();

    // localStorage o'zgarishlarini kuzatish
    window.addEventListener('storage', (event) => {
        if (event.key === 'userOrders') {
            loadOrders();
        }
    });
});

// Buyurtmalarni yuklash
async function loadOrders() {
    try {
        let orders = [];

        // API orqali buyurtmalarni olish (agar backend ishlamasa, localStorage dan olish)
        if (window.API && window.API.Orders && typeof window.API.Orders.getOrders === "function") {
            try {
                orders = await window.API.Orders.getOrders();
            } catch (apiError) {
                console.error("API orqali buyurtmalarni olishda xato:", apiError);
                orders = JSON.parse(localStorage.getItem("userOrders") || "[]");
            }
        } else {
            orders = JSON.parse(localStorage.getItem("userOrders") || "[]");
        }

        // Statistikani yangilash
        updateStats(orders);

        // Buyurtmalar ro'yxatini ko'rsatish
        displayOrders(orders);
    } catch (error) {
        console.error("Buyurtmalarni yuklashda xato:", error);
        displayOrders([]); // Xato bo'lsa bo'sh ro'yxat ko'rsatamiz
    }
}

// Statistikani yangilash
function updateStats(orders) {
    const totalOrders = orders.length;
    const activeOrders = orders.filter(order => order.status === "pending" || order.status === "in-progress").length;
    const completedOrders = orders.filter(order => order.status === "completed").length;

    const totalOrdersElement = document.getElementById("totalOrders");
    const activeOrdersElement = document.getElementById("activeOrders");
    const completedOrdersElement = document.getElementById("completedOrders");

    if (totalOrdersElement) totalOrdersElement.textContent = totalOrders;
    if (activeOrdersElement) activeOrdersElement.textContent = activeOrders;
    if (completedOrdersElement) completedOrdersElement.textContent = completedOrders;
}

// Buyurtmalar ro'yxatini ko'rsatish
function displayOrders(orders) {
    const ordersList = document.getElementById("orders-list");
    if (!ordersList) return;

    if (orders.length === 0) {
        ordersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-shopping-cart"></i>
                <h3>Buyurtmalar yo'q</h3>
                <p>Hozircha buyurtmalaringiz yo'q. Yangi buyurtma berish uchun "Yangi buyurtma" bo'limiga o'ting.</p>
            </div>
        `;
        return;
    }

    ordersList.innerHTML = orders.map(order => `
        <div class="order-item">
            <div class="order-header">
                <h3>Buyurtma #${order.id || "Noma'lum"}</h3>
                <span class="order-status ${order.status}">${order.status === "pending" ? "Kutilmoqda" : order.status === "in-progress" ? "Jarayonda" : "Tugallangan"}</span>
            </div>
            <div class="order-details">
                <p><strong>Xizmat:</strong> ${order.serviceType || "Noma'lum"}</p>
                <p><strong>Muammo:</strong> ${order.problem || "Noma'lum"}</p>
                <p><strong>Sana:</strong> ${new Date(order.createdAt || Date.now()).toLocaleDateString("uz-UZ")}</p>
                <p><strong>Shoshilinchlik:</strong> ${order.urgency || "Noma'lum"}</p>
            </div>
        </div>
    `).join("");
}

// Tab funksiyasi
function showTab(tabId) {
    const tabs = document.querySelectorAll(".tab-content");
    const tabButtons = document.querySelectorAll(".tab-btn");

    tabs.forEach(tab => {
        tab.classList.remove("active");
        if (tab.id === `${tabId}-tab`) {
            tab.classList.add("active");
        }
    });

    tabButtons.forEach(btn => {
        btn.classList.remove("active");
        if (btn.getAttribute("onclick") === `showTab('${tabId}')`) {
            btn.classList.add("active");
        }
    });
}

console.log("📊 Dashboard loaded!");