const API_URL = "http://127.0.0.1:5000";

export async function runScan({ code, requirements, config }) {
  const response = await fetch(`${API_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code,
      requirements,
      config,
    }),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
}

export async function runZipScan(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_URL}/scan-zip`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`ZIP API error: ${response.status}`);
  }

  return response.json();
}