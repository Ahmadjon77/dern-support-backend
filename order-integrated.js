// ===== ORDER FORM WITH API INTEGRATION =====
let currentUser = null;

// Initialize order form
document.addEventListener('DOMContentLoaded', () => {
    const orderForm = document.getElementById('orderForm');
    if (orderForm) {
        orderForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const user = JSON.parse(localStorage.getItem('currentUser'));
            if (!user) {
                alert('Iltimos, avval tizimga kiring!');
                window.location.href = 'login.html';
                return;
            }

            const formData = new FormData(orderForm);
            const orderData = {
                id: Date.now().toString(), // Unikal ID
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: formData.get('phone'),
                serviceType: formData.get('serviceType'),
                deviceType: formData.get('deviceType'),
                problem: formData.get('problem'),
                address: formData.get('address'),
                urgency: formData.get('urgency'),
                status: 'pending',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            // Buyurtmalarni localStorage dan olish
            const orders = JSON.parse(localStorage.getItem('userOrders') || '[]');
            orders.push(orderData);

            // localStorage ga saqlash
            localStorage.setItem('userOrders', JSON.stringify(orders));

            alert('Buyurtma muvaffaqiyatli yuborildi!');
            window.location.href = 'dashboard.html'; // Dashboardga qayta yo'naltirish
        });
    }
});

console.log("📦 Order integration loaded!");

// Pre-fill form with user data
function prefillUserData(user) {
  if (!user) return;
  const fields = {
    firstName: user.firstName || user.fullName?.split(" ")[0] || "",
    lastName: user.lastName || user.fullName?.split(" ")[1] || "",
    email: user.email || "",
    phone: user.phone || "",
  };
  Object.entries(fields).forEach(([fieldId, value]) => {
    const field = document.getElementById(fieldId);
    if (field && value) field.value = value;
  });
}

// Setup form handlers
function setupFormHandlers() {
  const orderForm = document.getElementById("orderForm");
  const phoneInput = document.getElementById("phone");

  if (phoneInput) {
    phoneInput.addEventListener("input", function () {
      formatPhoneNumber(this);
    });
  }

  if (orderForm) {
    console.log("Order form topildi");
    orderForm.addEventListener("submit", handleOrderSubmission);
  } else {
    console.log("Order form topilmadi");
  }
}

// Handle order form submission
async function handleOrderSubmission(e) {
  e.preventDefault();
  hideMessages();
  setLoading("orderBtn", true);

  try {
    const formData = new FormData(e.target);
    const orderData = buildOrderData(formData);

    if (!validateOrderData(orderData)) {
      setLoading("orderBtn", false);
      return;
    }

    let result;
    try {
      if (window.API.Orders) {
        result = await submitOrderToAPI(orderData);
        console.log("Buyurtma natijasi:", result);
        showSuccess("Buyurtmangiz muvaffaqiyatli qabul qilindi! Tez orada siz bilan bog'lanamiz.");
      } else {
        throw new Error("API.Orders not available");
      }
    } catch (apiError) {
      console.error("API submission failed:", apiError);
      result = submitOrderToLocalStorage(orderData);
      showSuccess("Buyurtmangiz saqlandi!");
    }

    e.target.reset();
    setTimeout(() => {
      window.location.href = currentUser ? "dashboard.html" : "index.html";
    }, 2000);
  } catch (error) {
    console.error("Order submission error:", error);
    showError("Buyurtma yuborishda xato yuz berdi: " + error.message);
  } finally {
    setLoading("orderBtn", false);
  }
}

// Build order data object
function buildOrderData(formData) {
  return {
    firstName: formData.get("firstName") || "",
    lastName: formData.get("lastName") || "",
    email: formData.get("email") || "",
    phone: formData.get("phone") || "",
    serviceType: formData.get("serviceType") || "",
    deviceType: formData.get("deviceType") || "",
    problem: formData.get("problem") || "",
    urgency: formData.get("urgency") || "low",
    address: formData.get("address") || "",
    notes: formData.get("notes") || "",
    status: "pending",
    userId: currentUser ? currentUser.id : null,
    createdAt: new Date().toISOString(),
  };
}

// Validate order data
function validateOrderData(orderData) {
  const requiredFields = ["firstName", "lastName", "email", "phone", "serviceType", "problem"];
  for (const field of requiredFields) {
    if (!orderData[field] || orderData[field].trim() === "") {
      showError(`${getFieldLabel(field)} maydoni to'ldirilishi shart!`);
      return false;
    }
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(orderData.email)) {
    showError("Email manzili noto'g'ri formatda!");
    return false;
  }
  if (orderData.phone.length < 10) {
    showError("Telefon raqami noto'g'ri formatda!");
    return false;
  }
  return true;
}

// Submit order to API
async function submitOrderToAPI(orderData) {
  const apiOrderData = {
    items: [{
      name: getServiceName(orderData.serviceType),
      description: orderData.problem,
      quantity: 1,
      price: getServicePrice(orderData.serviceType, orderData.urgency),
    }],
    totalAmount: getServicePrice(orderData.serviceType, orderData.urgency),
    shippingAddress: orderData.address || "",
    notes: `
Mijoz: ${orderData.firstName} ${orderData.lastName}
Email: ${orderData.email}
Telefon: ${orderData.phone}
Xizmat: ${getServiceName(orderData.serviceType)}
Qurilma: ${orderData.deviceType || "Kiritilmagan"}
Shoshilinchlik: ${getUrgencyText(orderData.urgency)}
Muammo: ${orderData.problem}
${orderData.notes ? "Qo'shimcha: " + orderData.notes : ""}
    `.trim(),
  };
  return await window.API.Orders.createOrder(apiOrderData);
}

// Submit order to localStorage
function submitOrderToLocalStorage(orderData) {
  const orderId = "ORD-" + String(Date.now()).slice(-6);
  const order = { id: orderId, ...orderData };
  const existingOrders = JSON.parse(localStorage.getItem("userOrders") || "[]");
  existingOrders.push(order);
  localStorage.setItem("userOrders", JSON.stringify(existingOrders));
  return order;
}

// Helper functions
function getServiceName(serviceType) {
  const services = { repair: "Kompyuter ta'mirlash", software: "Dasturiy ta'minot", consultation: "IT maslahat", maintenance: "Texnik xizmat" };
  return services[serviceType] || serviceType;
}

function getServicePrice(serviceType, urgency) {
  const basePrices = { repair: 100000, software: 80000, consultation: 50000, maintenance: 120000 };
  const urgencyMultipliers = { low: 1, medium: 1.2, high: 1.5, urgent: 2 };
  return Math.round((basePrices[serviceType] || 100000) * (urgencyMultipliers[urgency] || 1));
}

function getUrgencyText(urgency) {
  const urgencyTexts = { low: "Past - 2-3 kun ichida", medium: "O'rta - 1 kun ichida", high: "Yuqori - Bir necha soat ichida", urgent: "Juda shoshilinch - Darhol" };
  return urgencyTexts[urgency] || "Kiritilmagan";
}

function getFieldLabel(field) {
  const labels = { firstName: "Ism", lastName: "Familiya", email: "Email", phone: "Telefon", serviceType: "Xizmat turi", problem: "Muammo tavsifi" };
  return labels[field] || field;
}

function formatPhoneNumber(input) {
  let value = input.value.replace(/\D/g, "");
  if (value.startsWith("998")) value = value.substring(3);
  if (value.length >= 9) {
    value = value.substring(0, 9).replace(/(\d{2})(\d{3})(\d{2})(\d{2})/, "$1 $2 $3 $4");
    input.value = "+998 " + value;
  } else if (value.length > 0) input.value = "+998 " + value;
}

function showError(message) {
  const errorDiv = document.getElementById("error-message");
  if (errorDiv) {
    errorDiv.textContent = message;
    errorDiv.style.display = "block";
    window.scrollTo({ top: 0, behavior: "smooth" });
  } else {
    console.error("Xato: " + message);
  }
}

function showSuccess(message) {
  const successDiv = document.getElementById("success-message");
  if (successDiv) {
    successDiv.textContent = message;
    successDiv.style.display = "block";
    window.scrollTo({ top: 0, behavior: "smooth" });
  } else {
    console.log(message);
  }
}

function hideMessages() {
  const errorDiv = document.getElementById("error-message");
  const successDiv = document.getElementById("success-message");
  if (errorDiv) errorDiv.style.display = "none";
  if (successDiv) successDiv.style.display = "none";
}

function setLoading(buttonId, isLoading) {
  const button = document.getElementById(buttonId);
  if (!button) return;
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

console.log("🛒 Order form with API integration loaded!");