import mongoose from "mongoose";

export async function connectToDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI!)
    } catch (error) {
        console.error('Mongoddb connection error!', error);
        process.exit(1);
    }
} 