import User from '../Models/user.model.js';
import cloudinary from '../cloudinaryConfig.js';

export const profile =  async (req, res) => {
    try{
        const userId = req.user.id;
        const user = await User.findById(userId).select('-password');

        if(!user){
            return res.status(404).json({ msg: "user not found" });
        }

        return res.status(200).json(user);
    }
    catch(error){
        // console.log("Error in getUserProfile: ", error.message);
		res.status(500).json({ error: error.message });
    }
};

export const editProfile = async (req, res) => {
    try {
        const { jobType, username } = req.body;
        const image = req.file; // Multer handles the image file

        console.log('Request Body:', req.body);
        console.log('Request User:', req.user);

        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        const existingUser = await User.findById(req.user.id);
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Upload image to Cloudinary if it exists
        let imageUrl = existingUser.profileImage; // Default to existing image
        if (image) {
            const uploadResult = await new Promise((resolve, reject) => {
                cloudinary.v2.uploader.upload_stream(
                    { resource_type: 'image' },
                    (error, result) => {
                        if (error) return reject(error);
                        resolve(result);
                    }
                ).end(image.buffer); // Use buffer to handle file upload
            });
            // console.log('Cloudinary Upload Result:', uploadResult);
            imageUrl = uploadResult.secure_url;
        }

        // Update user profile in the database
        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            {
                name: username,
                jobType,
                profileImage: imageUrl, // Updated image URL
            },
            { new: true }
        );

        // console.log('Updated User:', updatedUser);
        // console.log("user", req.user);

        res.status(200).json({
            message: 'Profile updated successfully',
            user: updatedUser,
        });
    } catch (err) {
        // console.error('Error updating profile:', err);
        res.status(500).json({ error: 'Failed to update profile' });
    }
};

