import dotenv from "dotenv";
import { app } from "./app";

// Load environment variables
dotenv.config();

const PORT = process.env.PORT || 5000;

export const server = app.listen(PORT, () => {
  console.log(`BlockSubmit Backend running on port ${PORT}`);
  console.log(`Health endpoint: http://localhost:${PORT}/api/health`);
});
