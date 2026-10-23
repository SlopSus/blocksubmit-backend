# BlockSubmit Backend

Backend API service for the BlockSubmit academic integrity verification system.

## Setup

1. Copy `.env.example` to `.env` and fill in necessary configuration values:
   ```bash
   cp .env.example .env
   ```
2. Install dependencies (if not already installed):
   ```bash
   npm install
   ```

## Available Scripts

- **`npm run dev`**: Start the development server with live reload (`tsx`).
- **`npm run build`**: Compile TypeScript source to JavaScript (`dist/`).
- **`npm run type-check`**: Perform TypeScript type checking without emitting files.
- **`npm run start`**: Run the production build (`dist/index.js`).

## Health Endpoint

- `GET /api/health` — Returns service status and timestamp.
