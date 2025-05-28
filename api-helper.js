const API_BASE_URL = "http://localhost:3000/api";

// Token management
const TokenManager = {
  getToken: () => localStorage.getItem("authToken"),
  setToken: (token) => localStorage.setItem("authToken", token),
  removeToken: () => localStorage.removeItem("authToken"),
  isLoggedIn: () => !!localStorage.getToken(),
  getUserInfo: () => {
    const token = localStorage.getToken();
    if (!token) return null;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload;
    } catch {
      return null;
    }
  },
};

// API helper function
async function apiRequest(endpoint, options = {}) {
  const token = TokenManager.getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "So'rovda xato yuz berdi");
  }

  return response.json();
}

// Authentication functions
const Auth = {
  async login(username, password) {
    try {
      const data = await apiRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      TokenManager.setToken(data.token);
      localStorage.setItem("currentUser", JSON.stringify(data.user));
      return data;
    } catch (error) {
      throw error;
    }
  },
  async register(userData) {
    try {
      const data = await apiRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify(userData),
      });
      TokenManager.setToken(data.token);
      localStorage.setItem("currentUser", JSON.stringify(data.user));
      return data;
    } catch (error) {
      throw error;
    }
  },
  async getCurrentUser() {
    try {
      return await apiRequest("/auth/me");
    } catch (error) {
      TokenManager.removeToken();
      throw error;
    }
  },
  logout() {
    TokenManager.removeToken();
    localStorage.removeItem("currentUser");
    window.location.href = "/login.html";
  },
};

// Order functions
const Orders = {
  async createOrder(orderData) {
    return await apiRequest("/orders", { method: "POST", body: JSON.stringify(orderData) });
  },
  async getUserOrders() {
    return await apiRequest("/orders");
  },
  async getOrder(orderId) {
    return await apiRequest(`/orders/${orderId}`);
  },
};

// Product functions
const Products = {
  async getProducts() {
    return await apiRequest("/products");
  },
  async createProduct(productData) {
    return await apiRequest("/products", { method: "POST", body: JSON.stringify(productData) });
  },
};
// Masters functions
const Masters = {
  async createMaster(masterData) {
    const response = await apiRequest("/masters", {  // Bu yerda "/masters" ekanligiga e'tibor bering
      method: "POST",
      body: JSON.stringify(masterData),
    });
    return response;
  },
  async getMasters() {
    const response = await apiRequest("/masters", {
      method: "GET",
    });
    return response;
  },
};

// File upload functions
const FileUpload = {
  async uploadFile(file) {
    const formData = new FormData();
    formData.append("file", file);
    const token = TokenManager.getToken();
    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "File upload failed");
    }
    return await response.json();
  },
};

// Admin functions
const Admin = {
  async getUsers() {
    return await apiRequest("/users", { method: "GET" });
  },
  async getDashboardStats() {
    return await apiRequest("/admin/stats", { method: "GET" });
  },
};

// Utility functions
const Utils = {
  async isAdmin() {
    try {
      const user = await Auth.getCurrentUser();
      return user.role === "admin";
    } catch {
      return false;
    }
  },
  formatDate(dateString) {
    return new Date(dateString).toLocaleDateString("uz-UZ");
  },
  formatCurrency(amount) {
    return new Intl.NumberFormat("uz-UZ").format(amount) + " so'm";
  },
  showLoading(element) {
    if (element) element.innerHTML = '<div class="loading">Yuklanmoqda...</div>';
  },
  hideLoading(element, originalContent) {
    if (element) element.innerHTML = originalContent || "";
  },
  showMessage(message, type = "info") {
    const messageDiv = document.createElement("div");
    messageDiv.className = `message message-${type}`;
    messageDiv.textContent = message;
    messageDiv.style.cssText = `
      position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 5px;
      color: white; font-weight: bold; z-index: 1000;
      ${type === "success" ? "background: #4CAF50;" : ""}
      ${type === "error" ? "background: #f44336;" : ""}
      ${type === "info" ? "background: #2196F3;" : ""}
    `;
    document.body.appendChild(messageDiv);
    setTimeout(() => messageDiv.remove(), 3000);
  },
};

// Page protection
function requireAuth() {
  if (!TokenManager.isLoggedIn()) {
    window.location.href = "/login.html";
    return false;
  }
  return true;
}

async function requireAdmin() {
  if (!(await Utils.isAdmin())) {
    Utils.showMessage("Admin huquqi talab qilinadi!", "error");
    window.location.href = "/dashboard.html";
    return false;
  }
  return true;
}

// Auto logout on token expiry
function checkTokenExpiry() {
  const token = TokenManager.getToken();
  if (token) {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      const currentTime = Date.now() / 1000;
      if (payload.exp < currentTime) {
        TokenManager.removeToken();
        Utils.showMessage("Sessiya tugadi. Qayta kiring.", "error");
        window.location.href = "/login.html";
      }
    } catch (error) {
      console.error("Token check error:", error);
    }
  }
}
setInterval(checkTokenExpiry, 5 * 60 * 1000);

// Export for global use
window.API = { Auth, Orders, Products, FileUpload, Admin, Masters, Utils, TokenManager, requireAuth, requireAdmin };
console.log("🔗 API Helper yuklandi!");