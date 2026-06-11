/**
 * JavaScript module for a mixed Python/JS project.
 */

const axios = require("axios");

async function fetchHealth() {
  const response = await axios.get("http://localhost:8080/api/health");
  return response.data;
}

module.exports = { fetchHealth };
