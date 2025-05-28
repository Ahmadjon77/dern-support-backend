let currentAdmin = null;
let allOrders = [];
let allUsers = [];
let allProducts = [];
let allMasters = [];

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await requireAdmin();
    currentAdmin = await API.Auth.getCurrentUser();
    document.getElementById("adminName").textContent = `${currentAdmin.firstName} ${currentAdmin.lastName}`;
    await loadAdminDashboard();
  } catch (error) {
    console.error("Admin panel load error:", error);
    window.location.href = "login.html";
  }
});





// Master qo‘shish modalini ochish
function showAddMasterModal() {
    const modal = document.getElementById('addMasterModal');
    if (modal) modal.style.display = 'block';
}

// Modalni yopish
function closeModal() {
    const modal = document.getElementById('addMasterModal');
    if (modal) modal.style.display = 'none';
    const form = document.getElementById('addMasterForm');
    if (form) form.reset();
}

// Master qo‘shish
async function addMaster() {
    const form = document.getElementById('addMasterForm');
    if (!form) return;

    const masterData = {
        id: Date.now().toString(), // Unikal ID
        fullName: form.querySelector('#masterFullName').value,
        email: form.querySelector('#masterEmail').value,
        phone: form.querySelector('#masterPhone').value,
        specialization: form.querySelector('#masterSpecialization').value,
        role: 'master',
        isActive: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };

    if (!masterData.fullName || !masterData.email || !masterData.phone || !masterData.specialization) {
        alert("Barcha maydonlarni to'ldiring!");
        return;
    }

    // Masters ro'yxatini localStorage dan olish
    let masters = JSON.parse(localStorage.getItem('masters') || '[]');
    masters.push(masterData);
    localStorage.setItem('masters', JSON.stringify(masters));

    alert('Master muvaffaqiyatli qo‘shildi!');
    closeModal();
    loadAllMasters(); // Masters ro'yxatini yangilash
}

// Barcha masterlarni yuklash
function loadAllMasters() {
    const mastersList = document.getElementById('all-masters-list');
    if (!mastersList) return;

    const masters = JSON.parse(localStorage.getItem('masters') || '[]');

    if (masters.length === 0) {
        mastersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-user-tie"></i>
                <h3>Masters yo'q</h3>
                <p>Hozircha tizimda masterlar mavjud emas.</p>
            </div>
        `;
        return;
    }

    mastersList.innerHTML = masters.map(master => `
        <div class="admin-master-item">
            <div class="master-info">
                <h4>${master.fullName}</h4>
                <p><strong>Email:</strong> ${master.email}</p>
                <p><strong>Telefon:</strong> ${master.phone}</p>
                <div class="master-details">
                    <span class="master-specialization">${master.specialization}</span>
                    <span class="master-status">Holat: ${master.isActive ? 'Faol' : 'Nofaol'}</span>
                </div>
            </div>
            <div class="master-actions">
                <button class="btn btn-outline btn-sm" onclick="editMaster('${master.id}')">
                    <i class="fas fa-edit"></i> Tahrirlash
                </button>
            </div>
        </div>
    `).join('');
}

// Master tahrirlash (hozircha mock)
function editMaster(masterId) {
    console.log("Master tahrirlanmoqda:", masterId);
    // Tahrirlash logikasi qo'shilishi mumkin
}




async function loadAdminDashboard() {
  try {
    const stats = await API.Admin.getDashboardStats();
    document.getElementById("totalOrdersCount").textContent = stats.totalOrders;
    document.getElementById("totalUsersCount").textContent = stats.totalUsers;
    document.getElementById("totalMastersCount").textContent = stats.totalMasters || 0;
    document.getElementById("totalRevenue").textContent = API.Utils.formatCurrency(stats.totalRevenue || 0);
    await loadAllOrders();
  } catch (error) {
    console.error("Dashboard load error:", error);
    API.Utils.showMessage("Dashboard yuklanmadi: " + error.message, "error");
  }
}

function showAdminTab(tabName) {
  document.querySelectorAll(".tab-content").forEach((tab) => tab.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach((btn) => btn.classList.remove("active"));
  document.getElementById(`${tabName}-admin-tab`).classList.add("active");
  document.querySelector(`.tab-btn[onclick="showAdminTab('${tabName}')"]`).classList.add("active");

  switch (tabName) {
    case "orders":
      loadAllOrders();
      break;
    case "users":
      loadAllUsers();
      break;
    case "masters":
      loadAllMasters();
      break;
    case "products":
      loadAllProducts();
      break;
  }
}

async function loadAllOrders() {
  const container = document.getElementById("admin-orders-list");
  if (!container) return;
  API.Utils.showLoading(container);
  try {
    allOrders = await API.Orders.getUserOrders();
    displayAdminOrders(allOrders);
  } catch (error) {
    allOrders = JSON.parse(localStorage.getItem("userOrders") || "[]");
    displayAdminOrders(allOrders);
  } finally {
    API.Utils.hideLoading(container);
  }
}

function displayAdminOrders(orders) {
  const container = document.getElementById("admin-orders-list");
  if (!container) return;
  if (orders.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-shopping-cart"></i>
        <h3>Buyurtmalar yo'q</h3>
        <p>Hozircha tizimda buyurtmalar yo'q.</p>
      </div>
    `;
    return;
  }
  container.innerHTML = orders
    .map(
      (order) => `
      <div class="admin-order-item">
        <div class="order-header">
          <div class="order-info">
            <strong>Buyurtma #${order.id}</strong>
            <span>${order.firstName} ${order.lastName}</span>
            <span>${API.Utils.formatDate(order.createdAt)}</span>
          </div>
          <select onchange="updateOrderStatus('${order.id}', this.value)">
            <option value="pending" ${order.status === "pending" ? "selected" : ""}>Kutilmoqda</option>
            <option value="in-progress" ${order.status === "in-progress" ? "selected" : ""}>Jarayonda</option>
            <option value="completed" ${order.status === "completed" ? "selected" : ""}>Tugallangan</option>
            <option value="cancelled" ${order.status === "cancelled" ? "selected" : ""}>Bekor qilingan</option>
          </select>
        </div>
        <div class="order-details">
          <p><strong>Xizmat:</strong> ${getServiceName(order.serviceType)}</p>
          <p><strong>Muammo:</strong> ${order.problem}</p>
          <p><strong>Telefon:</strong> ${order.phone}</p>
          ${order.address ? `<p><strong>Manzil:</strong> ${order.address}</p>` : ""}
        </div>
      </div>
    `
    )
    .join("");
}

async function updateOrderStatus(orderId, newStatus) {
  try {
    await API.Orders.getOrder(orderId).then((order) => {
      order.status = newStatus;
      localStorage.setItem("userOrders", JSON.stringify(allOrders.map((o) => (o.id === orderId ? order : o))));
    });
    API.Utils.showMessage("Buyurtma statusi yangilandi!", "success");
    await loadAllOrders();
  } catch (error) {
    API.Utils.showMessage("Status yangilanmadi: " + error.message, "error");
  }
}

async function loadAllUsers() {
  const container = document.getElementById("admin-users-list");
  if (!container) return;
  API.Utils.showLoading(container);
  try {
    allUsers = await API.Admin.getUsers(); // Backenddan foydalanuvchilar ro'yxatini olish
    if (!allUsers || allUsers.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <i class="fas fa-users"></i>
          <h3>Foydalanuvchilar yo'q</h3>
          <p>Hozircha ro'yxatdan o'tgan foydalanuvchilar yo'q.</p>
        </div>
      `;
      return;
    }
    displayAdminUsers(allUsers);
  } catch (error) {
    console.error("Foydalanuvchilar yuklanmadi:", error);
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-users"></i>
        <h3>Foydalanuvchilar yo'q</h3>
        <p>Foydalanuvchilarni yuklashda xato yuz berdi.</p>
      </div>
    `;
  } finally {
    API.Utils.hideLoading(container);
  }
}

function displayAdminUsers(users) {
  const container = document.getElementById("admin-users-list");
  if (!container) return;
  if (users.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-users"></i>
        <h3>Foydalanuvchilar yo'q</h3>
        <p>Hozircha ro'yxatdan o'tgan foydalanuvchilar yo'q.</p>
      </div>
    `;
    return;
  }
  container.innerHTML = users
    .map(
      (user) => `
      <div class="admin-user-item">
        <div>
          <h4>${user.firstName} ${user.lastName}</h4>
          <p>Email: ${user.email}</p>
          <p>Telefon: ${user.phone || "Kiritilmagan"}</p>
          <p>Rol: <span style="background: ${user.role === "admin" ? "#28a745" : "#007bff"}; color: white; padding: 2px 8px; border-radius: 3px;">${user.role}</span></p>
        </div>
        <small>Ro'yxatdan o'tgan: ${API.Utils.formatDate(user.createdAt)}</small>
      </div>
    `
    )
    .join("");
}

async function loadAllProducts() {
  const container = document.getElementById("admin-products-list");
  if (!container) return;
  API.Utils.showLoading(container);
  try {
    allProducts = await API.Products.getProducts();
    displayAdminProducts(allProducts);
  } catch (error) {
    API.Utils.hideLoading(container, `
      <div class="empty-state">
        <i class="fas fa-box"></i>
        <h3>Mahsulotlar yo'q</h3>
        <p>Hozircha tizimda mahsulotlar yo'q.</p>
      </div>
    `);
  }
}

function displayAdminProducts(products) {
  const container = document.getElementById("admin-products-list");
  if (!container) return;
  if (products.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-box"></i>
        <h3>Mahsulotlar yo'q</h3>
        <p>Hozircha tizimda mahsulotlar yo'q.</p>
        <button class="btn btn-primary" onclick="showAddProductModal()">Yangi mahsulot qo'shish</button>
      </div>
    `;
    return;
  }
  container.innerHTML = products
    .map(
      (product) => `
      <div class="admin-product-item">
        <div class="product-info">
          <h4>${product.name}</h4>
          <p>${product.description || "Tavsif yo'q"}</p>
          <div class="product-details">
            <span class="product-price">${API.Utils.formatCurrency(product.price)}</span>
            <span class="product-category">${product.category}</span>
            <span class="product-stock">Zaxira: ${product.stock}</span>
          </div>
        </div>
        <div class="product-actions">
          <button class="btn btn-outline btn-sm" onclick="editProduct(${product.id})">
            <i class="fas fa-edit"></i> Tahrirlash
          </button>
        </div>
      </div>
    `
    )
    .join("");
}
async function loadAllUsers() {
  const container = document.getElementById("admin-users-list");
  if (!container) return;
  try {
    allUsers = await API.Admin.getUsers();
    if (!allUsers || allUsers.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <h3>Foydalanuvchilar yo'q</h3>
          <p>Hozircha ro'yxatdan o'tgan foydalanuvchilar yo'q.</p>
        </div>
      `;
      return;
    }
    container.innerHTML = allUsers
      .map(
        (user) => `
        <div class="admin-user-item">
          <div>
            <h4>${user.fullName || user.username}</h4>
            <p>Email: ${user.email}</p>
            <p>Telefon: ${user.phone || "Kiritilmagan"}</p>
            <p>Rol: <span style="background: ${user.role === "admin" ? "#28a745" : user.role === "master" ? "#ff9800" : "#007bff"}; color: white; padding: 2px 8px; border-radius: 3px;">${user.role}</span></p>
          </div>
          <small>Ro'yxatdan o'tgan: ${new Date(user.createdAt).toLocaleDateString()}</small>
        </div>
      `
      )
      .join("");
  } catch (error) {
    console.error("Foydalanuvchilar yuklanmadi:", error);
    container.innerHTML = `
      <div class="empty-state">
        <h3>Xato</h3>
        <p>Foydalanuvchilarni yuklashda xato yuz berdi.</p>
      </div>
    `;
  }
}

function displayAdminMasters(masters) {
  const container = document.getElementById("admin-masters-list");
  if (!container) return;
  if (masters.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-user-tie"></i>
        <h3>Masters yo'q</h3>
        <p>Hozircha tizimda masters yo'q.</p>
        <button class="btn btn-primary" onclick="showAddMasterModal()">Yangi master qo'shish</button>
      </div>
    `;
    return;
  }
  container.innerHTML = masters
    .map(
      (master) => `
      <div class="admin-master-item">
        <div class="master-info">
          <h4>${master.fullName}</h4>
          <p><strong>Email:</strong> ${master.email}</p>
          <p><strong>Telefon:</strong> ${master.phone}</p>
          <div class="master-details">
            <span class="master-specialization">${master.specialization}</span>
            <span class="master-status">Holat: ${master.isActive ? "Faol" : "Nofaol"}</span>
          </div>
        </div>
        <div class="master-actions">
          <button class="btn btn-outline btn-sm" onclick="editMaster(${master.id})">
            <i class="fas fa-edit"></i> Tahrirlash
          </button>
        </div>
      </div>
    `
    )
    .join("");
}

function showAddProductModal() {
  const modal = document.getElementById("addProductModal");
  if (modal) modal.style.display = "block";
}

function hideAddProductModal() {
  const modal = document.getElementById("addProductModal");
  if (modal) modal.style.display = "none";
  const form = document.getElementById("addProductForm");
  if (form) form.reset();
}

function getServiceName(serviceType) {
  const services = { repair: "Kompyuter ta'mirlash", software: "Dasturiy ta'minot", consultation: "IT maslahat", maintenance: "Texnik xizmat" };
  return services[serviceType] || serviceType;
}

// Master qo‘shish modalini ochish
function showAddMasterModal() {
  console.log("Master qo‘shish modal ochildi");
  const modal = document.getElementById("addMasterModal");
  if (modal) modal.style.display = "block";
}

// Modalni yopish funksiyasi
function closeModal() {
  const modal = document.getElementById("addMasterModal");
  if (modal) modal.style.display = "none";
  const form = document.getElementById("addMasterForm");
  if (form) form.reset();
}

// Masterni tahrirlash
function editMaster(masterId) {
  const master = allMasters.find(m => m.id === masterId);
  if (!master) {
    API.Utils.showMessage("Master topilmadi", "error");
    return;
  }
  // Modalni ochib, ma'lumotlarni yuklash
  console.log("Master tahrirlanmoqda:", masterId);
  showAddMasterModal();
  document.getElementById("masterFullName").value = master.fullName;
  document.getElementById("masterEmail").value = master.email;
  document.getElementById("masterPhone").value = master.phone;
  document.getElementById("masterSpecialization").value = master.specialization;
}

async function addMaster() {
  const masterData = {
    fullName: document.getElementById("masterFullName").value,
    email: document.getElementById("masterEmail").value,
    phone: document.getElementById("masterPhone").value,
    specialization: document.getElementById("masterSpecialization").value,
  };

  // Ma'lumotlarni tekshirish
  if (!masterData.fullName || !masterData.email || !masterData.phone || !masterData.specialization) {
    API.Utils.showMessage("Barcha maydonlarni to'ldiring!", "error");
    return;
  }

  try {
    const response = await API.Masters.createMaster(masterData);
    console.log("Master qo‘shildi:", response);
    API.Utils.showMessage("Master muvaffaqiyatli qo‘shildi!", "success");
    closeModal();
    await loadAllMasters(); // Masterlar ro'yxatini yangilash
  } catch (error) {
    console.error("Xato:", error.message);
    API.Utils.showMessage("Master qo‘shishda xato: " + error.message, "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const addProductForm = document.getElementById("addProductForm");
  if (addProductForm) {
    addProductForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const formData = new FormData(addProductForm);
      const productData = {
        name: formData.get("name"),
        price: Number.parseFloat(formData.get("price")),
        category: formData.get("category"),
        stock: Number.parseInt(formData.get("stock")),
        description: formData.get("description"),
      };
      try {
        await API.Products.createProduct(productData);
        API.Utils.showMessage("Mahsulot muvaffaqiyatli qo'shildi!", "success");
        hideAddProductModal();
        await loadAllProducts();
      } catch (error) {
        API.Utils.showMessage("Mahsulot qo'shilmadi: " + error.message, "error");
      }
    });
  }

  // Master formasi uchun submit hodisasi
  const addMasterForm = document.getElementById("addMasterForm");
  if (addMasterForm) {
    addMasterForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await addMaster();
    });
  }
});

window.showAdminTab = showAdminTab;
window.logout = () => API.Auth.logout();
setInterval(loadAdminDashboard, 60000);