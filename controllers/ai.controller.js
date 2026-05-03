const axios = require("axios");
const db = require("../config/db");

exports.chat = async (req, res) => {
  const { message } = req.body;

  try {
    // 🔥 نجيب الرحلات
    const [trips] = await db.query(`
      SELECT from_city, to_city, departure_time, price
      FROM trips
      LIMIT 10
    `);

    // 🔥 AI request
    const response = await axios.post(
      "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
      {
        inputs: `
You are JustBot for a bus app.

Answer ONLY about trips.

Trips data:
${JSON.stringify(trips)}

User: ${message}
        `,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.HF_TOKEN}`,
        },
      }
    );

    const reply =
      response.data?.[0]?.generated_text || "ما قدرت أفهم 😅";

    res.json({
      reply,
      trips,
    });

  } catch (err) {
    console.error("AI ERROR:", err.response?.data || err.message);

    res.status(500).json({
      message: "AI error",
    });
  }
};