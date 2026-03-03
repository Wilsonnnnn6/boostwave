const orderForm = document.getElementById("orderForm");
const formMessage = document.getElementById("formMessage");
const platformSelect = document.getElementById("platform");
const planSelect = document.getElementById("plan");

// Quick-fill form fields when user selects a package card.
document.querySelectorAll(".select-package").forEach((button) => {
  button.addEventListener("click", () => {
    platformSelect.value = button.dataset.platform;
    planSelect.value = button.dataset.plan;
    formMessage.textContent = `Selected ${button.dataset.platform} - ${button.dataset.plan} (${button.dataset.price}).`;
    document.getElementById("order").scrollIntoView({ behavior: "smooth" });
  });
});

orderForm.addEventListener("submit", (event) => {
  event.preventDefault();

  const data = new FormData(orderForm);
  const name = data.get("name");
  const platform = data.get("platform");
  const plan = data.get("plan");

  formMessage.textContent = `Thanks ${name}. Your ${platform} ${plan} order has been received. We will contact you shortly.`;
  orderForm.reset();
});
