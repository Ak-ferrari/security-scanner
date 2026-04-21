import React from "react";

function FileUpload({ title, value, setValue, placeholder, accept }) {
  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if (!selectedFile) return;

    const reader = new FileReader();

    reader.onload = (e) => {
      setValue(e.target.result);
    };

    reader.readAsText(selectedFile);
  };

  const handleTextChange = (event) => {
    setValue(event.target.value);
  };

  return (
    <div className="input-block">
      <label className="label">{title}</label>

      <input
        type="file"
        className="file-input"
        accept={accept}
        onChange={handleFileChange}
      />

      <textarea
        className="text-area"
        value={value}
        onChange={handleTextChange}
        placeholder={placeholder}
      />
    </div>
  );
}

export default FileUpload;