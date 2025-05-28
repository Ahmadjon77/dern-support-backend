// Mock users database (faqat test uchun, backendda ishlatilmaydi)
const mockUsers = [
  { id: 1, email: "admin@dernsupport.uz", password: "admin123", role: "admin", firstName: "Admin", lastName: "User" },
  { id: 2, email: "master@dernsupport.uz", password: "master123", role: "master", firstName: "Master", lastName: "Technician" },
  { id: 3, email: "user@dernsupport.uz", password: "user123", role: "user", firstName: "Test", lastName: "User" },
];

// Get registered users from localStorage
function getRegisteredUsers() {
  return JSON.parse(localStorage.getItem("registeredUsers") || "[]");
}

// Save registered users to localStorage
function saveRegisteredUsers(users) {
  localStorage.setItem("registeredUsers", JSON.stringify(users));
}
// UI helper functions
function showError(message) {
  const errorDiv = document.getElementById("error-message");
  if (errorDiv) {
    errorDiv.textContent = message;
    errorDiv.style.display = "block";
  } else {
    console.error("Xato: " + message);
    alert("Xato: " + message);
  }
}

function showSuccess(message) {
  const successDiv = document.getElementById("success-message");
  if (successDiv) {
    successDiv.textContent = message;
    successDiv.style.display = "block";
  } else {
    console.log(message);
    alert(message);
  }
}

function hideMessages() {
  const errorDiv = document.getElementById("error-message");
  const successDiv = document.getElementById("success-message");
  if (errorDiv) errorDiv.style.display = "none";
  if (successDiv) successDiv.style.display = "none";
}

function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const eye = document.getElementById(inputId + "-eye");
  if (input && eye) {
    input.type = input.type === "password" ? "text" : "password";
    eye.className = input.type === "password" ? "fas fa-eye" : "fas fa-eye-slash";
  }
}

function setLoading(buttonId, isLoading) {
  const button = document.getElementById(buttonId);
  if (button) {
    const text = button.querySelector(".btn-text");
    const spinner = button.querySelector(".btn-loading");
    if (isLoading) {
      if (text) text.style.display = "none";
      if (spinner) spinner.style.display = "inline-block";
      button.disabled = true;
    } else {
      if (text) text.style.display = "inline";
      if (spinner) spinner.style.display = "none";
      button.disabled = false;
    }
  }
}

function formatPhoneNumber(input) {
  let value = input.value.replace(/\D/g, "");
  if (value.startsWith("998")) value = value.substring(3);
  if (value.length >= 9) {
    value = value.substring(0, 9).replace(/(\d{2})(\d{3})(\d{2})(\d{2})/, "$1 $2 $3 $4");
    input.value = "+998 " + value;
  } else if (value.length > 0) input.value = "+998 " + value;
}

// Authentication functions
document.addEventListener("DOMContentLoaded", () => {
  console.log("auth.js loaded, API:", window.API);
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  if (loginForm) {
    console.log("Login form topildi");
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideMessages();
      setLoading("loginBtn", true);

      const formData = new FormData(loginForm);
      const email = formData.get("email").trim();
      const password = formData.get("password");

      if (!email || !password) {
        showError("Email va parol talab qilinadi");
        setLoading("loginBtn", false);
        return;
      }

      try {
        const response = await window.API.Auth.login({ email, password });
        const user = response.user;
        console.log("Login natijasi:", response);
        localStorage.setItem("authToken", response.token);
        localStorage.setItem("currentUser", JSON.stringify(user));

        showSuccess("Muvaffaqiyatli kirdingiz! Yo'naltirilmoqda...");
        setTimeout(() => {
          if (user.role === "admin") {
            window.location.href = "admin.html";
          } else if (user.role === "master") {
            window.location.href = "master.html";
          } else {
            window.location.href = "dashboard.html";
          }
        }, 1000);
      } catch (error) {
        console.error("Login xatosi:", error);
        showError(error.message || "Login xatosi yuz berdi");
      } finally {
        setLoading("loginBtn", false);
      }
    });
  }

  if (registerForm) {
    console.log("Register form topildi");
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideMessages();
      setLoading("registerBtn", true);

      const formData = new FormData(registerForm);
      const email = formData.get("email").trim();
      const password = formData.get("password");
      const confirmPassword = formData.get("confirmPassword");
      const firstName = formData.get("firstName");
      const lastName = formData.get("lastName");
      const phone = formData.get("phone");

      if (!email || !password || !firstName || !lastName) {
        showError("Email, parol, ism va familiya talab qilinadi");
        setLoading("registerBtn", false);
        return;
      }

      if (password !== confirmPassword) {
        showError("Parollar mos kelmaydi!");
        setLoading("registerBtn", false);
        return;
      }

      if (password.length < 6) {
        showError("Parol kamida 6 ta belgidan iborat bo'lishi kerak!");
        setLoading("registerBtn", false);
        return;
      }

      try {
        const result = await window.API.Auth.register({
          email,
          password,
          firstName,
          lastName,
          phone,
          role: "user",
        });
        console.log("Ro'yxatdan o'tish natijasi:", result);
        showSuccess("Ro'yxatdan o'tish muvaffaqiyatli! Tizimga kirishingiz mumkin.");
        setTimeout(() => {
          window.location.href = "dashboard.html";
        }, 2000);
      } catch (error) {
        console.error("Ro'yxatdan o'tish xatosi:", error);
        showError(error.message || "Ro'yxatdan o'tishda xato yuz berdi");
      } finally {
        setLoading("registerBtn", false);
      }
    });
  }

  // Phone formatting
  const phoneInputs = document.querySelectorAll('input[type="tel"]');
  phoneInputs.forEach((input) => {
    input.addEventListener("input", () => formatPhoneNumber(input));
  });

  // Password toggle
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  passwordInputs.forEach((input) => {
    const inputId = input.id;
    if (inputId) {
      const eye = document.getElementById(inputId + "-eye");
      if (eye) {
        eye.addEventListener("click", () => togglePassword(inputId));
      }
    }
  });
});

// Global functions
window.logout = () => {
  window.API.Auth.logout();
};

window.checkAuth = () => {
  const user = localStorage.getItem("currentUser");
  const token = localStorage.getItem("authToken");
  if (!user || !token) {
    window.location.href = "dashboard.html";
    return null;
  }
  return JSON.parse(user);
};