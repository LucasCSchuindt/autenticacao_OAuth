fetch("/api/me", { credentials: "same-origin" })
  .then((r) => (r.ok ? r.json() : null))
  .then((user) => {
    const status = document.getElementById("status");
    const dot = document.getElementById("statusDot");
    if (user) {
      status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
      dot.classList.add("is-active");
      dot.classList.remove("is-idle");
    } else {
      status.textContent = "Nenhuma sessão neste navegador.";
      dot.classList.add("is-idle");
      dot.classList.remove("is-active");
    }
  });
