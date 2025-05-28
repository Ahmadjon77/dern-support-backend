// Master panel functionality
document.addEventListener('DOMContentLoaded', async () => {
    console.log("master.js loaded, API:", window.API);

    // Foydalanuvchi ma'lumotlarini tekshirish va master rolini talab qilish
    const user = await requireMaster();
    if (!user) return;

    // Master ismini ko'rsatish
    const masterNameElement = document.getElementById('masterName');
    if (masterNameElement) {
        masterNameElement.textContent = `${user.firstName} ${user.lastName}`;
    }

    // Master dashboardini yuklash
    loadMasterDashboard();

    // Profil ma'lumotlarini yuklash
    loadMasterProfile();
});

// Master rolini talab qilish
async function requireMaster() {
    const user = checkAuth();
    if (!user) {
        window.location.href = "login.html";
        return null;
    }

    if (user.role !== "master") {
        alert("Bu sahifaga faqat masterlar kira oladi!");
        window.location.href = "login.html";
        return null;
    }

    // Agar API mavjud bo'lsa, serverdan foydalanuvchi ma'lumotlarini qayta tekshirish
    if (window.API && window.API.Auth && window.API.Auth.getCurrentUser) {
        try {
            const serverUser = await window.API.Auth.getCurrentUser();
            if (serverUser.role !== "master") {
                alert("Bu sahifaga faqat masterlar kira oladi!");
                window.location.href = "login.html";
                return null;
            }
            return serverUser;
        } catch (error) {
            console.error("Serverdan foydalanuvchi ma'lumotlarini olishda xato:", error);
            window.location.href = "login.html";
            return null;
        }
    }
    return user;
}

// Show master tab
function showMasterTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    const selectedTab = document.getElementById(tabName + '-master-tab');
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to clicked button
    const clickedButton = document.querySelector(`button[onclick="showMasterTab('${tabName}')"]`);
    if (clickedButton) {
        clickedButton.classList.add('active');
    }

    // Load tab content
    switch(tabName) {
        case 'new-orders':
            loadNewOrders();
            break;
        case 'my-orders':
            loadMyOrders();
            break;
        case 'completed':
            loadCompletedOrders();
            break;
    }
}

// Load master dashboard
function loadMasterDashboard() {
    const user = JSON.parse(localStorage.getItem('currentUser'));
    const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
    const myOrders = orders.filter(order => order.masterId === user.id);

    // Update stats
    const pendingOrders = orders.filter(o => o.status === 'pending' && !o.masterId);
    const inProgressOrders = myOrders.filter(o => o.status === 'in-progress');
    const completedOrders = myOrders.filter(o => o.status === 'completed');

    document.getElementById('pendingOrdersCount').textContent = pendingOrders.length;
    document.getElementById('inProgressOrdersCount').textContent = inProgressOrders.length;
    document.getElementById('completedOrdersCount').textContent = completedOrders.length;
    document.getElementById('averageRating').textContent = user.rating || '0.0'; // Mock rating o'rniga haqiqiy reyting

    // Load initial tab content
    loadNewOrders();
}

// Load new orders
function loadNewOrders() {
    const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
    const newOrders = orders.filter(order => order.status === 'pending' && !order.masterId);
    const ordersList = document.getElementById('new-orders-list');

    if (!ordersList) return;

    if (newOrders.length === 0) {
        ordersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-clock"></i>
                <h3>Yangi buyurtmalar yo'q</h3>
                <p>Hozircha qabul qilish uchun yangi buyurtmalar mavjud emas.</p>
            </div>
        `;
        return;
    }

    const ordersHTML = newOrders.map(order => `
        <div class="order-card">
            <div class="order-header">
                <div class="order-id">${order.id || 'Noma\'lum'}</div>
                <div class="order-date">${new Date(order.createdAt || Date.now()).toLocaleDateString('uz-UZ')}</div>
            </div>
            <div class="order-info">
                <h4>${order.firstName || 'Noma\'lum'} ${order.lastName || ''}</h4>
                <p><i class="fas fa-envelope"></i> ${order.email || 'Noma\'lum'}</p>
                <p><i class="fas fa-phone"></i> ${order.phone || 'Noma\'lum'}</p>
                <p><i class="fas fa-cog"></i> ${getServiceName(order.serviceType)}</p>
                ${order.deviceType ? `<p><i class="fas fa-desktop"></i> ${order.deviceType}</p>` : ''}
                ${order.urgency ? `<p><i class="fas fa-exclamation-triangle"></i> ${getUrgencyName(order.urgency)}</p>` : ''}
            </div>
            <div class="order-problem">
                <h5>Muammo tavsifi:</h5>
                <p>${order.problem || 'Noma\'lum'}</p>
            </div>
            ${order.address ? `
                <div class="order-problem">
                    <h5>Manzil:</h5>
                    <p>${order.address}</p>
                </div>
            ` : ''}
            <div class="order-actions">
                <button class="btn btn-accept" onclick="acceptOrder('${order.id}')">
                    <i class="fas fa-check"></i> Qabul qilish
                </button>
                <button class="btn btn-outline" onclick="viewOrderDetails('${order.id}')">
                    <i class="fas fa-eye"></i> Batafsil
                </button>
            </div>
        </div>
    `).join('');

    ordersList.innerHTML = ordersHTML;
}

// Load my orders
function loadMyOrders() {
    const user = JSON.parse(localStorage.getItem('currentUser'));
    const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
    const myOrders = orders.filter(order => order.masterId === user.id && order.status === 'in-progress');
    const ordersList = document.getElementById('my-orders-list');

    if (!ordersList) return;

    if (myOrders.length === 0) {
        ordersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-cog"></i>
                <h3>Jarayondagi buyurtmalar yo'q</h3>
                <p>Hozircha jarayonda bo'lgan buyurtmalaringiz yo'q.</p>
            </div>
        `;
        return;
    }

    const ordersHTML = myOrders.map(order => `
        <div class="order-card">
            <div class="order-header">
                <div class="order-id">${order.id || 'Noma\'lum'}</div>
                <div class="order-date">${new Date(order.createdAt || Date.now()).toLocaleDateString('uz-UZ')}</div>
            </div>
            <div class="order-info">
                <h4>${order.firstName || 'Noma\'lum'} ${order.lastName || ''}</h4>
                <p><i class="fas fa-envelope"></i> ${order.email || 'Noma\'lum'}</p>
                <p><i class="fas fa-phone"></i> ${order.phone || 'Noma\'lum'}</p>
                <p><i class="fas fa-cog"></i> ${getServiceName(order.serviceType)}</p>
            </div>
            <div class="order-problem">
                <h5>Muammo tavsifi:</h5>
                <p>${order.problem || 'Noma\'lum'}</p>
            </div>
            <div class="order-actions">
                <button class="btn btn-complete" onclick="completeOrder('${order.id}')">
                    <i class="fas fa-check-circle"></i> Tugallash
                </button>
                <button class="btn btn-outline" onclick="contactCustomer('${order.phone}')">
                    <i class="fas fa-phone"></i> Bog'lanish
                </button>
            </div>
        </div>
    `).join('');

    ordersList.innerHTML = ordersHTML;
}

// Load completed orders
function loadCompletedOrders() {
    const user = JSON.parse(localStorage.getItem('currentUser'));
    const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
    const completedOrders = orders.filter(order => order.masterId === user.id && order.status === 'completed');
    const ordersList = document.getElementById('completed-orders-list');

    if (!ordersList) return;

    if (completedOrders.length === 0) {
        ordersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle"></i>
                <h3>Tugallangan buyurtmalar yo'q</h3>
                <p>Hozircha tugallangan buyurtmalaringiz yo'q.</p>
            </div>
        `;
        return;
    }

    const ordersHTML = completedOrders.map(order => `
        <div class="order-card">
            <div class="order-header">
                <div class="order-id">${order.id || 'Noma\'lum'}</div>
                <div class="order-date">${new Date(order.createdAt || Date.now()).toLocaleDateString('uz-UZ')}</div>
            </div>
            <div class="order-info">
                <h4>${order.firstName || 'Noma\'lum'} ${order.lastName || ''}</h4>
                <p><i class="fas fa-cog"></i> ${getServiceName(order.serviceType)}</p>
                <p><i class="fas fa-calendar"></i> Tugallangan: ${new Date(order.completedAt || order.updatedAt || Date.now()).toLocaleDateString('uz-UZ')}</p>
            </div>
            <div class="order-problem">
                <h5>Muammo tavsifi:</h5>
                <p>${order.problem || 'Noma\'lum'}</p>
            </div>
            <div class="order-actions">
                <button class="btn btn-outline" onclick="viewOrderDetails('${order.id}')">
                    <i class="fas fa-eye"></i> Batafsil
                </button>
            </div>
        </div>
    `).join('');

    ordersList.innerHTML = ordersHTML;
}

// Accept order
function acceptOrder(orderId) {
    if (confirm('Bu buyurtmani qabul qilishni xohlaysizmi?')) {
        const user = JSON.parse(localStorage.getItem('currentUser'));
        const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
        const orderIndex = orders.findIndex(o => o.id === orderId);

        if (orderIndex !== -1) {
            orders[orderIndex].status = 'in-progress';
            orders[orderIndex].masterId = user.id;
            orders[orderIndex].masterName = `${user.firstName} ${user.lastName}`;
            orders[orderIndex].acceptedAt = new Date().toISOString();
            orders[orderIndex].updatedAt = new Date().toISOString();

            localStorage.setItem('userOrders', JSON.stringify(orders));
            loadMasterDashboard();
            showMasterTab('new-orders');

            alert('Buyurtma muvaffaqiyatli qabul qilindi!');
        } else {
            alert('Buyurtma topilmadi!');
        }
    }
}

// Complete order
function completeOrder(orderId) {
    if (confirm('Bu buyurtmani tugallangan deb belgilashni xohlaysizmi?')) {
        const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
        const orderIndex = orders.findIndex(o => o.id === orderId);

        if (orderIndex !== -1) {
            orders[orderIndex].status = 'completed';
            orders[orderIndex].completedAt = new Date().toISOString();
            orders[orderIndex].updatedAt = new Date().toISOString();

            localStorage.setItem('userOrders', JSON.stringify(orders));
            loadMasterDashboard();
            showMasterTab('my-orders');

            alert('Buyurtma tugallandi!');
        } else {
            alert('Buyurtma topilmadi!');
        }
    }
}

// Contact customer
function contactCustomer(phone) {
    if (phone) {
        window.open(`tel:${phone}`, '_self');
    } else {
        alert('Telefon raqami mavjud emas');
    }
}

// Load master profile
function loadMasterProfile() {
    const user = JSON.parse(localStorage.getItem('currentUser'));
    if (!user) return;

    document.getElementById('profileFirstName').value = user.firstName || '';
    document.getElementById('profileLastName').value = user.lastName || '';
    document.getElementById('profileEmail').value = user.email || '';
    document.getElementById('profilePhone').value = user.phone || '';
    document.getElementById('profileSpecialty').value = user.specialty || 'general';
    document.getElementById('profileBio').value = user.bio || '';

    // Profil formasi submit hodisasi
    const profileForm = document.getElementById('masterProfileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(profileForm);

            // Foydalanuvchi ma'lumotlarini yangilash
            user.firstName = formData.get('firstName');
            user.lastName = formData.get('lastName');
            user.phone = formData.get('phone');
            user.specialty = formData.get('specialty');
            user.bio = formData.get('bio');
            user.updatedAt = new Date().toISOString();

            // localStorage'ga saqlash
            localStorage.setItem('currentUser', JSON.stringify(user));

            // Master ismini yangilash
            const masterNameElement = document.getElementById('masterName');
            if (masterNameElement) {
                masterNameElement.textContent = `${user.firstName} ${user.lastName}`;
            }

            alert('Profil ma\'lumotlari saqlandi!');
        });
    }
}

// Helper functions
function getServiceName(serviceType) {
    const services = {
        'repair': 'Kompyuter ta\'mirlash',
        'software': 'Dasturiy ta\'minot',
        'consultation': 'IT maslahat',
        'maintenance': 'Texnik xizmat'
    };
    return services[serviceType] || serviceType;
}

function getUrgencyName(urgency) {
    const urgencies = {
        'low': 'Past - 2-3 kun ichida',
        'medium': 'O\'rta - 1 kun ichida',
        'high': 'Yuqori - Bir necha soat ichida',
        'urgent': 'Juda shoshilinch - Darhol'
    };
    return urgencies[urgency] || urgency;
}

function viewOrderDetails(orderId) {
    const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
    const order = orders.find(o => o.id === orderId);
    if (order) {
        alert(`Buyurtma tafsilotlari:\n\nID: ${order.id || 'Noma\'lum'}\nMijoz: ${order.firstName || 'Noma\'lum'} ${order.lastName || ''}\nEmail: ${order.email || 'Noma\'lum'}\nTelefon: ${order.phone || 'Noma\'lum'}\nXizmat: ${getServiceName(order.serviceType)}\nQurilma: ${order.deviceType || 'Kiritilmagan'}\nMuammo: ${order.problem || 'Noma\'lum'}\nManzil: ${order.address || 'Kiritilmagan'}\nHolat: ${order.status || 'Noma\'lum'}\nSana: ${new Date(order.createdAt || Date.now()).toLocaleDateString('uz-UZ')}`);
    } else {
        alert('Buyurtma topilmadi!');
    }
}

console.log("🔧 Master panel loaded!");