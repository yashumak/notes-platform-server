import mongoose from "mongoose";

export const setGridFsFileUserId = async (bucketName, fileId, userId) => {
  const result = await mongoose.connection.db
    .collection(`${bucketName}.files`)
    .updateOne({ _id: fileId }, { $set: { user_id: userId } });

  if (result.matchedCount !== 1) {
    throw new Error(`Could not assign owner to ${bucketName} file`);
  }
};
