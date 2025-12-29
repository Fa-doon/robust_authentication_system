import mongoose from "mongoose";

export async function connectToDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI!);
        console.log('Mongo connection successfully established');
    } catch (error) {
        console.error('Mongodb connection error!', error);
        process.exit(1);
    }
} 