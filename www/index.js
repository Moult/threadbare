document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('ol.threads li.thread').forEach(li => {
    li.addEventListener('click', (e) => {
      window.location.href = li.querySelector('a').href;
    });
  });
});
