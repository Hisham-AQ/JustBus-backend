const axios = require("axios");
const db = require("../config/db");

exports.chat = async (req, res) => {
  const { message } = req.body;

  try {
    // 🔥 نجيب الرحلات (context)
    const [trips] = await db.query(`
      SELECT from_city, to_city, departure_time, price
      FROM trips
      LIMIT 10
    `);

    // 🔥 نبني prompt ذكي
    const prompt = `
You are JustBot, a smart assistant for a transport app.

You can:
- chat normally
- answer about trips
- be friendly

If user asks about trips → use this data:
${JSON.stringify(trips)}

User: ${message}
`;

    const response = await axios.post(
      "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
      {
        inputs: prompt,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.HF_TOKEN}`,
        },
      }
    );

    const reply =
      response.data?.[0]?.generated_text || "مش فاهم عليك 😅";

    res.json({
      reply,
      trips,
    });

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({
      message: err.response?.data || err.message
    });
  }
};