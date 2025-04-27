document.addEventListener("DOMContentLoaded", () => {
    const textarea = document.getElementById("content");

    // Live preview
    const preview = document.createElement("div");
    preview.id = "markdown-preview";
    preview.innerHTML = "<p>Live preview will appear here…</p>";
    textarea.parentNode.insertBefore(preview, textarea.nextSibling);

    const updatePreview = () => {
      const rawMarkdown = textarea.value;
      const rawHTML = marked.parse(rawMarkdown, { breaks: true });
      const cleanHTML = DOMPurify.sanitize(rawHTML);
      preview.innerHTML = cleanHTML;
    };

    // Debounced update on input
    textarea.addEventListener("input", debounce(updatePreview, 200));

    function debounce(fn, delay) {
      let timeout;
      return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn.apply(this, args), delay);
      };
    }

    // Upload
    const uploadLink = document.getElementById("upload-link");
    uploadLink.addEventListener("click", (e) => {
      e.preventDefault();

      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".jpg,.jpeg,.png,.pdf,.txt,.zip,.ifc";
      input.style.display = "none";

      input.addEventListener("change", () => {
        const file = input.files[0];
        if (!file) return;

        const originalHTML = uploadLink.innerHTML;
        uploadLink.innerHTML = `<span class="spinner"></span> Uploading...`;
        uploadLink.style.pointerEvents = "none";
        uploadLink.style.opacity = "0.6";

        const formData = new FormData();
        formData.append("attachment", file);
        formData.append("csrf", document.querySelector("input[name=csrf]").value);
        formData.append("useJS", "true");

        fetch(window.location.origin + "/upload", {
          method: "POST",
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          uploadLink.innerHTML = originalHTML;
          uploadLink.style.pointerEvents = "auto";
          uploadLink.style.opacity = "1";
            console.log(data);
            console.log(data.success);
            console.log(data.url);

          if (data.success && data.url && data.csrf) {
            document.querySelectorAll('input[name="csrf"]').forEach(el => {
              el.value = data.csrf;
            });
            insertAtCursor(textarea, data.url.match(/\.(jpe?g|png|gif)$/i) ? `![](${data.url})` : `[${file.name}](${data.url})`);
          } else {
            alert("Upload failed");
              console.log(data);
          }
        })
        .catch(err => {
          uploadLink.innerHTML = originalHTML;
          uploadLink.style.pointerEvents = "auto";
          uploadLink.style.opacity = "1";
        console.error(err);
          alert("Upload system failed.");
            console.log(err);
        });
      });

      document.body.appendChild(input);
      input.click();
      input.remove();
    });

    function insertAtCursor(textarea, text) {
          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          const before = textarea.value.substring(0, start);
          const after = textarea.value.substring(end);
          textarea.value = before + text + after;
          textarea.selectionStart = textarea.selectionEnd = start + text.length;
          textarea.focus();
        }


    // Mentions

  const dropdown = document.createElement("div");
  dropdown.classList.add("mention-dropdown");
  dropdown.style.display = "none";
  document.body.appendChild(dropdown);

  let suggestions = [];
  let selectedIndex = -1;
  let triggerStart = 0;

  function positionDropdown() {
    const rect = textarea.getBoundingClientRect();
    dropdown.style.top = (rect.top + window.scrollY + textarea.offsetHeight) + "px";
    dropdown.style.left = (rect.left + window.scrollX) + "px";
    dropdown.style.width = rect.width + "px";
  }

  function closeDropdown() {
    dropdown.style.display = "none";
    suggestions = [];
    selectedIndex = -1;
  }

  textarea.addEventListener("input", async () => {
    const cursorPos = textarea.selectionStart;
    const textUpToCursor = textarea.value.slice(0, cursorPos);
    const match = textUpToCursor.match(/@([\w-]{1,})$/);

    if (!match) {
      closeDropdown();
      return;
    }

    const term = match[1];
    triggerStart = cursorPos - term.length - 1;

    try {
        const match = window.location.pathname.match(/^\/thread\/(\d+)/);
        const threadId = match ? match[1] : null;
        let res;
        if (threadId) {
          res = await fetch(`/mention/${threadId}/@${encodeURIComponent(term)}`);
        } else {
          res = await fetch(`/mention/@${encodeURIComponent(term)}`);
        }
      suggestions = await res.json();

      if (suggestions.length === 0) {
        closeDropdown();
        return;
      }

      dropdown.innerHTML = '';
      suggestions.forEach((name, i) => {
        const item = document.createElement("div");
        item.textContent = name;
        if (i === 0) {
          item.classList.add("selected");
          selectedIndex = 0;
        }
        item.addEventListener("mousedown", (e) => {
          e.preventDefault(); // prevents textarea from losing focus
          completeWith(name);
        });
        dropdown.appendChild(item);
      });

      positionDropdown();
      dropdown.style.display = "block";
    } catch (err) {
      console.error("Autocomplete error", err);
      closeDropdown();
    }
  });

  function completeWith(username) {
    const before = textarea.value.slice(0, triggerStart);
    const after = textarea.value.slice(textarea.selectionStart);
    textarea.value = before + '@' + username + ' ' + after;
    const cursor = before.length + username.length + 2;
    textarea.setSelectionRange(cursor, cursor);
    textarea.focus();
    closeDropdown();
  }

  textarea.addEventListener("keydown", (e) => {
    if (dropdown.style.display === "none") return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedIndex = (selectedIndex + 1) % suggestions.length;
      updateSelection();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedIndex = (selectedIndex - 1 + suggestions.length) % suggestions.length;
      updateSelection();
    } else if (e.key === "Tab" || e.key === "Enter") {
      e.preventDefault();
      if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
        completeWith(suggestions[selectedIndex]);
      }
    } else if (e.key === "Escape") {
      closeDropdown();
    }
  });

  function updateSelection() {
    [...dropdown.children].forEach((el, i) => {
      el.classList.toggle("selected", i === selectedIndex);
    });
  }

  document.addEventListener("click", (e) => {
    if (!dropdown.contains(e.target) && e.target !== textarea) {
      closeDropdown();
    }
  });

  window.addEventListener("resize", closeDropdown);
});

