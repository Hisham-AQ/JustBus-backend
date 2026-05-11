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
        price
      FROM trips
      LIMIT 10
    `);

    const prompt = `

You are JustBot.

You help students with:
- bus trips
- booking
- schedules
- prices
- stations

Answer shortly and clearly.

Trips:
${JSON.stringify(trips)}

User:
${message}

`;

    const response =
      await axios.post(

        "https://openrouter.ai/api/v1/chat/completions",

        {
          model:
            "mistralai/mistral-7b-instruct",

          messages: [
            {
              role: "user",
              content: prompt,
            },
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