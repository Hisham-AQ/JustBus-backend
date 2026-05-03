const db = require("../config/db");
const OpenAI = require("openai");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// --- Helpers ---
function normalizeCity(s = "") {
  return s.trim().toLowerCase();
}

async function fetchTrips({ from, to, date, maxPrice, limit = 10 }) {
  let sql = `
    SELECT 
      id, from_city, to_city, departure_time, arrival_time,
      price, available_seats
    FROM trips
    WHERE 1=1
  `;
  const params = [];

  if (from) {
    sql += " AND TRIM(LOWER(from_city)) = TRIM(LOWER(?))";
    params.push(from);
  }

  if (to) {
    sql += " AND TRIM(LOWER(to_city)) = TRIM(LOWER(?))";
    params.push(to);
  }

  if (date) {
    sql += " AND DATE(trip_date) = DATE(?)";
    params.push(date);
  }

  if (maxPrice != null) {
    sql += " AND price <= ?";
    params.push(maxPrice);
  }

  sql += " ORDER BY departure_time LIMIT ?";
  params.push(limit);

  const [rows] = await db.query(sql, params);
  return rows;
}

// --- Controller ---
exports.chat = async (req, res) => {
  const { message } = req.body;

  try {
    // 1) AI Parsing → JSON Intent
    const parseCompletion = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      temperature: 0,
      messages: [
        {
          role: "system",
          content: `
Extract user intent as STRICT JSON only (no text).

Schema:
{
  "intent": "search_trips | greeting | other",
  "from": string|null,
  "to": string|null,
  "date": string|null,        // format: YYYY-MM-DD if present
  "maxPrice": number|null
}

Rules:
- Understand Arabic and English.
- If cities mentioned, put exact names (e.g., "Amman", "JUST university").
- If no info → null.
- Return ONLY JSON.
          `,
        },
        { role: "user", content: message },
      ],
    });

    let parsed;
    try {
      parsed = JSON.parse(
        parseCompletion.choices[0].message.content.trim()
      );
    } catch {
      parsed = { intent: "other" };
    }

    // 2) Decision + DB Query
    let trips = [];
    if (parsed.intent === "search_trips") {
      trips = await fetchTrips({
        from: parsed.from,
        to: parsed.to,
        date: parsed.date,
        maxPrice: parsed.maxPrice,
      });
    }

    // 3) AI Response (Natural answer)
    const answerCompletion = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      temperature: 0.3,
      messages: [
        {
          role: "system",
          content: `
You are JustBot for a bus app.

- Answer in Arabic if user used Arabic, otherwise English.
- Be concise and helpful.
- If intent is not transport → say: "I only help with trips and transport."
- If no trips found → say politely no results.
- If trips exist → summarize best options (time + price).

Trips data:
${JSON.stringify(trips)}
          `,
        },
        { role: "user", content: message },
      ],
    });

    const reply = answerCompletion.choices[0].message.content;

    return res.json({
      reply,
      trips, // ترجعها للـ UI (مهم لزر "احجز")
      intent: parsed.intent,
      filters: parsed,
    });
  } catch (err) {
    console.error("AI ERROR:", err);
    return res.status(500).json({ message: "AI error" });
  }
};