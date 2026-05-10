const db = require("../config/db");

const {
  GoogleGenerativeAI,
} = require("@google/generative-ai");

const genAI =
  new GoogleGenerativeAI(
    process.env.GEMINI_API_KEY
  );

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

    const model =
      genAI.getGenerativeModel({
       model: "gemini-pro",
      });

    const prompt = `

You are JustBot.

You help students with:
- bus trips
- booking
- schedules
- prices
- stations

Answer shortly and clearly.

Available trips:
${JSON.stringify(trips)}

User:
${message}

`;

    const result =
      await model.generateContent(
        prompt
      );

    const reply =
      result.response.text();

    res.json({
      reply,
      trips,
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "AI error",
    });
  }
};