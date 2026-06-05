const axios = require("axios");
const db = require("../../config/db");

// ================= AI =================
exports.chat = async (req, res) => {

  const { message } = req.body;

  try {

    const [trips] = await db.query(`
      SELECT
  t.id,
  t.from_city,
  t.to_city,
  t.departure_time,
  t.arrival_time,
  t.price,
  t.available_seats,
  t.status,
  t.trip_date,
  u.name AS driver_name,

  b.bus_number,
  b.capacity

FROM trips t

LEFT JOIN drivers d
ON t.driver_id = d.id

LEFT JOIN users u
ON d.user_id = u.id

LEFT JOIN buses b
ON d.bus_id = b.id

WHERE t.status IN ('scheduled','ongoing')
ORDER BY t.trip_date ASC
LIMIT 20
    `);

    const lowerMessage = message.toLowerCase();

    const isTripQuestion =
      lowerMessage.includes("trip") ||
      lowerMessage.includes("trips") ||
      lowerMessage.includes("available trip") ||
      lowerMessage.includes("available trips") ||
      lowerMessage.includes("show trips") ||
      lowerMessage.includes("show available trips")

    if (isTripQuestion) {
      return res.json({
        reply: "",
        trips
      });
    }


    const prompt = `
You are JustBot.

You are the AI assistant of JustBus.

You help students with:

- trip booking
- routes
- schedules
- ticket QR codes
- wallet
- rewards
- parcels
- special trips
- panic alerts
- stations

Rules:

- Answer briefly.
- Use only available data.
- If data does not exist say:
"I don't have that information."

Current Date:
${new Date().toISOString()}

Available trips:

${JSON.stringify(trips)}

User Question:
${message}
`;

    const response =
      await axios.post(

        "https://openrouter.ai/api/v1/chat/completions",

        {
          model:
            "openai/gpt-3.5-turbo",

          messages: [
            {
              role: "system",
              content: `
           You are JustBot.

           You are the official assistant of the JustBus system.

         Rules:
         - Answer briefly and clearly.
         - Use only provided information.
         - Never invent data.
         - If information is unavailable, say:
           "I don't have that information."
         - Be friendly and professional.
             `
            },
            {
              role: "user",
              content: prompt,
            }
          ],
        },

        {
          headers: {

            Authorization:
              `Bearer ${process.env.OPENROUTER_API_KEY}`,

            "Content-Type":
              "application/json",
          },
        }
      );

    const reply =
      response.data
        ?.choices?.[0]
        ?.message?.content ||
      "ما قدرت أفهم 😅";

    res.json({
      reply,
      trips: [],
    });

  } catch (err) {

    console.error(
      err.response?.data ||
      err.message
    );

    res.status(500).json({
      message: "AI error",
    });
  }
};