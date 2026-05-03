const axios = require("axios");
const db = require("../config/db");

exports.chat = async (req, res) => {
  const { message } = req.body;

  try {
    const [trips] = await db.query(`
      SELECT from_city, to_city, departure_time, price
      FROM trips
      LIMIT 5
    `);

    const prompt = `
You are JustBot. You help with trips and chat normally.

Trips:
${JSON.stringify(trips)}

User: ${message}
`;

    const response = await axios.post(
      "https://api-inference.huggingface.co/models/facebook/blenderbot-400M-distill",
      {
        inputs: prompt,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.HF_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    const reply =
      response.data?.[0]?.generated_text || "مش فاهم عليك 😅";

    res.json({ reply });

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ message: "AI error" });
  }
};