/*
  Simple manual smoke test script for POST /api/groups
  Usage:
    TEST_API_URL=http://localhost:5001/api node scripts/create_group_test.js
  Required env vars:
    TEST_TOKEN - Bearer token (access token) for an existing user
    MEMBERS - JSON array of member ids (optional)
    NAME - group name (optional)

  This script is intentionally minimal: it doesn't create users or tokens.
*/

import fetch from "node-fetch";

const API_URL = process.env.TEST_API_URL || "http://localhost:5001/api";
const TOKEN = process.env.TEST_TOKEN;
const NAME = process.env.NAME || "Group from smoke script";
let MEMBERS = [];
try {
  if (process.env.MEMBERS) MEMBERS = JSON.parse(process.env.MEMBERS);
} catch (e) {
  console.error('MEMBERS must be a JSON array string, e.g. "["id1","id2"]"');
  process.exit(1);
}

if (!TOKEN) {
  console.error("Please set TEST_TOKEN env var to an access token.");
  process.exit(1);
}

(async () => {
  try {
    const res = await fetch(`${API_URL}/groups`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`,
      },
      body: JSON.stringify({ name: NAME, members: MEMBERS }),
    });

    const body = await res.json();
    console.log("status", res.status);
    console.log("body", body);
  } catch (e) {
    console.error("Request failed", e);
  }
})();
