document.addEventListener('DOMContentLoaded', () => {
  const toggles = document.querySelectorAll('.toggle-password');
  toggles.forEach(button => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.target);
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      button.textContent = isPassword ? 'Hide' : 'Show';
    });
  });

  const fileInput = document.getElementById('fileInput');
  const fileName = document.getElementById('fileName');
  if (fileInput && fileName) {
    fileInput.addEventListener('change', () => {
      fileName.textContent = fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'No file selected';
    });
  }

  const dropzone = document.getElementById('dropzone');
  if (dropzone && fileInput && fileName) {
    ['dragover', 'dragenter'].forEach(evt => dropzone.addEventListener(evt, e => {
      e.preventDefault(); dropzone.style.borderColor = '#C084FC';
    }));
    ['dragleave', 'drop'].forEach(evt => dropzone.addEventListener(evt, e => {
      e.preventDefault(); dropzone.style.borderColor = 'rgba(192,132,252,0.25)';
    }));
    dropzone.addEventListener('drop', e => {
      const files = e.dataTransfer.files;
      if (files && files.length) {
        const dt = new DataTransfer();
        dt.items.add(files[0]);
        fileInput.files = dt.files;
        fileName.textContent = files[0].name;
      }
    });
  }
});
