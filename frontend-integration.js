// API Base URL
const API_BASE_URL = "http://localhost:3000/api";

// Token management
const TokenManager = {
  getToken: () => localStorage.getItem("authToken"),
  setToken: (token) => localStorage.setItem("authToken", token),
  removeToken: () => localStorage.removeItem("authToken"),
  isLoggedIn: () => !!localStorage.getItem("authToken"),
  getUserInfo: () => {
    const token = localStorage.getItem("authToken");
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

// Authentication API
const Auth = {
  async login(credentials) {
    try {
      const data = await apiRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify(credentials),
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
    window.location.href = "/index.html";
  },
};

// Orders API
const Orders = {
  async createOrder(orderData) {
    try {
      const data = await apiRequest("/orders", {
        method: "POST",
        body: JSON.stringify(orderData),
      });
      return data;
    } catch (error) {
      throw error;
    }
  },
};

// Export global API object
window.API = { Auth, TokenManager, Orders };
console.log("🔗 API Helper yuklandi!");