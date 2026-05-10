const axios = require("axios");
const db = require("../config/db");

exports.chat = async (req, res) => {

  const { message } = req.body;

  try {

    const [trips] = await db.query(`
      SELECT
        from_city,
        to_city,
        departure_time,
        price,
        available_seats
      FROM trips
      LIMIT 10
    `);

    const prompt = `

You are JustBot.

You help students with:
- bus trips
- booking
- schedules
- stations
- prices

Answer shortly and clearly.

Trips:
${JSON.stringify(trips)}

User:
${message}

`;

    const response =
      await axios.post(

        `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,

        {
          contents: [
            {
              parts: [
                {
                  text: prompt,
                },
              ],
            },
          ],
        }
      );

    const reply =

      response.data
        ?.candidates?.[0]
        ?.content?.parts?.[0]
        ?.text ||

      "ما قدرت أفهم 😅";

    res.json({
      reply,
      trips,
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