import { connectToDB } from "./config/db";
import dotenv from 'dotenv';
import http from 'http';
import app from "./app";

dotenv.config();




async function startServer() {
    await connectToDB;

    const server = http.createServer(app);

    server.listen(process.env.PORT, () => {
        console.log(`Server is now listening on port ${process.env.PORT}`);
    })
}

startServer().catch(err => {
    console.log(`Error while starting the server`, err);
    process.exit(1);
})