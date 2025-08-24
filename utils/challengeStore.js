const challengeStore = new Map();

const cleanupExpiredChallenges = () => {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000;
    for (const [key, value] of challengeStore.entries()) {
        if (value.timestamp && now - value.timestamp > maxAge) {
            console.log("🧹 Cleaning up expired challenge:", key);
            challengeStore.delete(key);
        }
    }
};

setInterval(cleanupExpiredChallenges, 60000);

export default challengeStore;
